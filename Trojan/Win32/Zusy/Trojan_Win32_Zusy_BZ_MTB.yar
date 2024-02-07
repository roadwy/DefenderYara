
rule Trojan_Win32_Zusy_BZ_MTB{
	meta:
		description = "Trojan:Win32/Zusy.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {4a 69 61 66 67 6a 69 6f 73 61 67 6f 69 73 68 67 } //02 00  Jiafgjiosagoishg
		$a_01_1 = {4f 48 6f 61 66 6a 69 6f 67 61 73 65 6a 67 66 69 6f 73 61 65 67 } //02 00  OHoafjiogasejgfiosaeg
		$a_01_2 = {50 4f 6b 6a 61 73 64 6b 6a 67 73 6f 69 67 73 65 72 75 67 68 } //02 00  POkjasdkjgsoigserugh
		$a_01_3 = {52 70 6f 61 65 6f 70 66 67 61 65 67 69 6f 73 6a 67 73 } //01 00  Rpoaeopfgaegiosjgs
		$a_01_4 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //00 00  WaitForSingleObject
	condition:
		any of ($a_*)
 
}