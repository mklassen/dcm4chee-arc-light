import { Pipe, PipeTransform } from '@angular/core';

@Pipe({
  name: 'dicomDate'
})
export class DicomDatePipe implements PipeTransform {

    transform(attrs: any, tag?: any): any {
        try {
            let value = attrs[tag].Value[0];
            return value.substr(0, 4) + '/' + value.substr(4, 2) + '/' + value.substr(6, 2);
        } catch (e) {
            return '';
        }
    }

}
