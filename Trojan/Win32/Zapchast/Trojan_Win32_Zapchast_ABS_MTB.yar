
rule Trojan_Win32_Zapchast_ABS_MTB{
	meta:
		description = "Trojan:Win32/Zapchast.ABS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 "
		
	strings :
		$a_03_0 = {2b 2c 11 07 6f 90 01 01 00 00 0a 74 90 01 01 00 00 01 0d 09 6f 90 01 01 00 00 0a 2c 17 09 6f 90 01 01 00 00 0a 17 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 0b 11 07 6f 90 01 01 00 00 0a 2d cb 90 00 } //10
		$a_03_1 = {07 8e 69 1b 59 8d 90 01 01 00 00 01 13 04 07 1b 11 04 16 07 8e 69 1b 59 28 90 01 01 00 00 0a 11 04 90 00 } //10
		$a_01_2 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //1 GetFolderPath
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=22
 
}