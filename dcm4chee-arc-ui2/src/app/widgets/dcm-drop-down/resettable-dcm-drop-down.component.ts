import {Component, Input} from "@angular/core";
import {animate, state, style, transition, trigger} from "@angular/animations";
import {DcmDropDownComponent} from "./dcm-drop-down.component";
import {SelectDropdown} from "../../interfaces";

@Component({
    selector: 'resettable-dcm-drop-down',
    templateUrl: './dcm-drop-down.component.html',
    styleUrls: ['./dcm-drop-down.component.scss'],
    animations:[
        trigger("showHide",[
            state("show",style({
                padding:"*",
                height:'*',
                opacity:1
            })),
            state("hide",style({
                padding:"0",
                opacity:0,
                height:'0px',
                margin:"0"
            })),
            transition("show => hide",[
                animate('0.1s')
            ]),
            transition("hide => show",[
                animate('0.2s cubic-bezier(.52,-0.01,.15,1)')
            ])
        ])
    ]
})
export class ResettableDcmDropDownComponent extends DcmDropDownComponent{
    @Input() editable:boolean = false;
    @Input() min:number;
    @Input() max:number;
    @Input() showStar:boolean = false;
    @Input('model')
    set model(value){
        super.model = value;
        this._optionsTree.forEach(optionBlock=>{
            optionBlock.options.forEach((option:SelectDropdown<any>)=>{
                option.selected = false;
            });
        });
        this.selectElementInTreeByValue(this.multiSelectValue);
    }
}