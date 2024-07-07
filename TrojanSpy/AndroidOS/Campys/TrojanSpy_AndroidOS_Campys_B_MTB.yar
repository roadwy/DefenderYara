
rule TrojanSpy_AndroidOS_Campys_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Campys.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {77 77 77 2e 66 69 72 6d 77 61 72 65 73 79 73 74 65 6d 75 70 64 61 74 65 2e 63 6f 6d } //2 www.firmwaresystemupdate.com
		$a_00_1 = {75 70 6c 6f 61 64 2d 66 69 6c 65 2e 70 68 70 } //1 upload-file.php
		$a_00_2 = {67 65 74 2d 66 75 6e 63 74 69 6f 6e 2e 70 68 70 } //1 get-function.php
		$a_00_3 = {52 65 63 6f 72 64 43 61 6c 6c } //1 RecordCall
		$a_00_4 = {41 6c 6c 53 6d 73 } //1 AllSms
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}