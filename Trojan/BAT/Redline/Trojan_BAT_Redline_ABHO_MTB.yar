
rule Trojan_BAT_Redline_ABHO_MTB{
	meta:
		description = "Trojan:BAT/Redline.ABHO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {5b 6f 1f 00 00 0a 6f 22 00 00 0a fe 09 06 00 71 18 00 00 01 20 01 00 00 00 6f 23 00 00 0a 28 2d 00 00 06 fe 0e 03 00 fe 09 0a 00 fe 0c 03 00 81 04 00 00 1b fe 09 05 00 71 1b 00 00 01 fe 09 06 00 71 18 00 00 01 6f 24 00 00 0a 20 01 00 00 00 73 25 00 00 0a fe 0e 04 00 fe 09 0b 00 fe 0c 04 00 81 1d 00 00 01 fe 09 00 00 20 04 00 00 00 54 fe 0c 05 00 2a } //2
		$a_01_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {47 65 74 42 79 74 65 73 } //1 GetBytes
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}