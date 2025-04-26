
rule TrojanSpy_AndroidOS_SAgnt_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_02_0 = {2f 73 6d 73 ?? ?? ?? ?? 2e 70 68 70 3f 75 70 6c 6f 61 64 73 6d 73 3d } //2
		$a_00_1 = {55 70 6c 6f 61 64 46 69 6c 65 50 68 70 } //1 UploadFilePhp
		$a_00_2 = {2f 53 6d 73 2e 74 78 74 } //1 /Sms.txt
		$a_00_3 = {55 70 6c 6f 61 64 4b 69 6c 6c } //1 UploadKill
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}