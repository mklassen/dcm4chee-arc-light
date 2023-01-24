import { Pipe, PipeTransform } from '@angular/core';

@Pipe({
  name: 'dicomTime'
})
export class DicomTimePipe implements PipeTransform {

    transform(attrs: any, tag?: any): any {
        try {
            let value = attrs[tag].Value[0];
            return value.substr(0, 2) + ':' + value.substr(2, 2);
        } catch (e) {
            return '';
        }
    }

}
