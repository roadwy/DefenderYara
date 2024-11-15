
rule Backdoor_AndroidOS_SAgnt_B_MTB{
	meta:
		description = "Backdoor:AndroidOS/SAgnt.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 73 6d 61 72 74 6e 73 2f 65 61 73 79 63 6f 6d 70 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //1 com/smartns/easycomp/MainActivity
		$a_01_1 = {46 49 4c 45 5f 53 45 4e 44 49 4e 47 5f 55 52 4c 5f 46 49 4c 45 5f 4e 41 4d 45 } //1 FILE_SENDING_URL_FILE_NAME
		$a_01_2 = {2f 73 64 63 61 72 64 2f 4d 79 52 65 70 55 72 6c 53 6d 73 } //1 /sdcard/MyRepUrlSms
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}