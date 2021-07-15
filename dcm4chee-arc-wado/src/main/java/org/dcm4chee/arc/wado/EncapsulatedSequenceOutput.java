package org.dcm4chee.arc.wado;

import org.dcm4che3.data.Attributes;
import org.dcm4che3.data.VR;
import org.dcm4che3.io.DicomInputStream;
import org.dcm4chee.arc.retrieve.RetrieveContext;
import org.dcm4chee.arc.retrieve.RetrieveService;
import org.dcm4chee.arc.store.InstanceLocations;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.core.StreamingOutput;
import java.io.IOException;
import java.io.OutputStream;

/**
 * @author Igor Solovey <igor.solovey@gmail.com>
 * @since Jul 2021
 */
public class EncapsulatedSequenceOutput implements StreamingOutput {

    private static final Logger LOG = LoggerFactory.getLogger(EncapsulatedSequenceOutput.class);

    private static final int BUFFER_SIZE = 8192;

    // Robarts^CFMM^DicomRawAppend always creates new DICOM files and stores
    // results in private creator 0x0177,0x0010 under data element 0x0177,0x1000
    private static final int PRIVATE_CREATOR_TAG = 24576016; //0x01770010
    private static final int ZIP_TAG = 24580096; //0x01771000
    private static final String CREATOR_ID = "Robarts^CFMM^DicomRawAppend";

    private byte[] buffer;
    private final RetrieveContext ctx;
    private final InstanceLocations inst;

    private byte[] buffer() {
        if (buffer == null)
            buffer = new byte[BUFFER_SIZE];
        return buffer;
    }

    public EncapsulatedSequenceOutput(RetrieveContext ctx, InstanceLocations inst) {
        this.ctx = ctx;
        this.inst = inst;
    }

    @Override
    public void write(final OutputStream out) throws IOException {
        DicomInputStream dis = _validInstance(ctx, inst);
        byte[] tail = new byte[2];

        if (dis.tag() != ZIP_TAG || (dis.vr() != VR.UN && dis.vr() != VR.SQ)) {
            throw new IOException("Parsed ZIP file not at correct tag: " +
                    dis.tag() + ", " + dis.vr().toString());
        }

        // Disable the stop handler
        // TODO: ?
        dis.setDicomInputHandler(dis);

        // Loop through the items in the sequence
        dis.readHeader();
        if (dis.tag() != -73728) { // Start of item   0xFFFEE000
            throw new IOException("Encapsulated ZIP file format is incorrect. No Item start: " +
                    dis.tag() + " != -73728");
        }

        byte[] buf = buffer();

        while (true) {
            // Each Item contains one Data Element of Encapsulated Document (VR=OB)
            dis.readHeader();
            if (dis.tag() == 4325393) {      // Encapsulated Document (0x00420011)
                int totalread = 0;
                int vallen = dis.length();

                // Make sure the buffer is at least two bytes long, and no longer than the item length
                if (buf.length < 2)
                    buf = new byte[Math.min(65536, vallen)];

                int maxRead = Math.min(buf.length, vallen - totalread);
                int len;
                while (maxRead > 0) {
                    len = dis.read(buf, 0, maxRead);
                    totalread += len;
                    maxRead = Math.min(buf.length, vallen - totalread);
                    // The ZIP file will end with padding of either
                    // The last two bytes of each block can only be written once it is determined that
                    // this is the last block of data.
                    // 01
                    // 00 02
                    if (maxRead > 1) {
                        // More than two bytes left to read so everything can be written
                        out.write(buf, 0, len);
                    } else if (maxRead > 0) {
                        // One byte to read, so the current last byte might be padding
                        out.write(buf, 0, len - 1);
                        tail[0] = buf[len - 1];
                    } else {
                        // Nothing left to read, i.e. last read for item
                        if (len > 1) {
                            // More than two bytes read, so write everything except the last two bytes
                            out.write(buf, 0, len - 2);
                            // Store the last two bytes in the tail
                            System.arraycopy(buf, len - 2, tail, 0, 2);
                        } else if (len > 0) {
                            // One byte read, so add it to the two byte tail
                            tail[1] = buf[0];
                        } else {
                            // Failed to read any data
                            throw new IOException("No ZIP data read.");
                        }
                    }
                }
            } else
                throw new IOException("Encapsulated ZIP file format is incorrect. Wrong Element tag: " +
                        dis.tag() + " != 4325393");

            dis.readHeader();

            // Skip an end of item tag
            if (dis.tag() == -73715) {
                if (dis.length() > 0) {
                    LOG.warn("Item Delimitation Item (FFFE,E00D) with non-zero Item Length:" +
                            dis.length() + " at pos: " + dis.getTagPosition() + " - try to skip length");
                    dis.skip(dis.length());
                }
                dis.readHeader();
            }

            // Check for Start of Item or End of Sequence
            if (dis.tag() == -73728) {       // Start of item   0xFFFEE000
                // Write the tail, since there is another item to be read
                out.write(tail);
            } else if (dis.tag() == -73507) {  // End of Sequence 0xFFFEE0DD
                // No more items so write out any data that is not padding
                if (tail[1] < 2) {
                    out.write(tail, 0, 1);
                }
                break;
            } else
                throw new IOException("Encapsulated ZIP file format is incorrect. No Item start or Sequence End: " +
                        dis.tag() + " != -73728 or -73507");
        }
    }


    private static DicomInputStream _validInstance(RetrieveContext ctx, InstanceLocations inst) throws IOException {
        RetrieveService service = ctx.getRetrieveService();
        DicomInputStream dis = service.openDicomInputStream(ctx, inst);
        // Read up to and including the PRIVATE_CREATOR_TAG attribute
        Attributes attrs = dis.readDataset(-1, o -> o.tag() > PRIVATE_CREATOR_TAG);

        if (attrs.contains(PRIVATE_CREATOR_TAG)) {

            String creator_id;
            if (attrs.getVR(PRIVATE_CREATOR_TAG) == VR.OB) {
                creator_id = new String(attrs.getBytes(PRIVATE_CREATOR_TAG));
                LOG.warn("Wrong type for " + PRIVATE_CREATOR_TAG + ". Converting OB to LO.");
            } else
                creator_id = attrs.getString(PRIVATE_CREATOR_TAG);

            // Check that the private creator id flag matches, a different private creator may have used the same tag
            // which means that value of CREATOR_ID will not be present as it is always the first private
            // creator and therefore always claims PRIVATE_CREATOR_TAG if it is present
            if (creator_id.startsWith(CREATOR_ID)) {

                // Read up to but not including the ZIP_TAG private attribute (VR=SQ)
                //attrs = dis.readDataset(-1, o -> o.tag() == ZIP_TAG );

                // Check that the ZIP_TAG was found and is SQ or UN
                if (dis.tag() == ZIP_TAG && (dis.vr() == VR.SQ || dis.vr() == VR.UN)) {
                    return dis;
                } else throw new IOException("Private content does not have the right tag or VR");
            } else
                throw new IOException("Incorrect value of CFMM Private Creator tag (0177, 1000). Should be =" + CREATOR_ID);
        } else throw new IOException("Missing CFMM Private Creator tag (0177, 1000)");
    }

    public static boolean isValidInstance(RetrieveContext ctx, InstanceLocations inst) {
        try {
            _validInstance(ctx, inst);
            return true;
        } catch (IOException e) {
            return false;
        }
    }
}
