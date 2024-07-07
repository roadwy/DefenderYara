
rule Trojan_Win64_IcedID_DJY_MTB{
	meta:
		description = "Trojan:Win64/IcedID.DJY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 6f 75 61 43 41 54 52 74 6b } //5 AouaCATRtk
		$a_01_1 = {48 67 68 63 67 78 61 73 68 66 67 66 73 66 67 64 66 } //5 Hghcgxashfgfsfgdf
		$a_01_2 = {49 61 55 62 37 64 36 63 6e 55 68 31 76 } //3 IaUb7d6cnUh1v
		$a_01_3 = {47 59 66 41 67 74 65 71 63 4c 43 4c 64 } //3 GYfAgteqcLCLd
		$a_01_4 = {4f 7a 58 47 4e 70 } //1 OzXGNp
		$a_01_5 = {4c 65 52 56 49 49 36 59 6d 78 73 48 6c 51 } //1 LeRVII6YmxsHlQ
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=9
 
}