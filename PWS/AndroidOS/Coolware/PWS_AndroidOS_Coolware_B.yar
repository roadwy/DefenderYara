
rule PWS_AndroidOS_Coolware_B{
	meta:
		description = "PWS:AndroidOS/Coolware.B,SIGNATURE_TYPE_DEXHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_01_0 = {74 6f 41 65 73 44 65 63 72 79 70 74 } //1 toAesDecrypt
		$a_01_1 = {74 6f 41 65 73 45 6e 63 72 79 70 74 } //1 toAesEncrypt
		$a_01_2 = {4c 71 71 71 2f 77 77 77 2f 65 65 65 2f 65 76 2f 42 } //1 Lqqq/www/eee/ev/B
		$a_01_3 = {68 65 6c 6c 6f 57 6f 72 6c 64 49 61 6d 42 6f 79 } //4 helloWorldIamBoy
		$a_01_4 = {49 61 6d 42 6f 79 68 65 6c 6c 6f 77 6f 72 6c 64 } //4 IamBoyhelloworld
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*4+(#a_01_4  & 1)*4) >=11
 
}