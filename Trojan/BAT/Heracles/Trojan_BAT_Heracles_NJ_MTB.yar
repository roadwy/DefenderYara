
rule Trojan_BAT_Heracles_NJ_MTB{
	meta:
		description = "Trojan:BAT/Heracles.NJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {11 05 25 4b 11 0c 11 0f 1f 0f 5f 95 61 54 } //5
		$a_81_1 = {5f 63 72 79 70 74 65 64 2e 65 78 65 } //2 _crypted.exe
		$a_81_2 = {66 69 6c 65 5f } //2 file_
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*5+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*1) >=10
 
}