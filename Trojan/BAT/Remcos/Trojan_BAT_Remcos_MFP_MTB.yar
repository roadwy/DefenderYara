
rule Trojan_BAT_Remcos_MFP_MTB{
	meta:
		description = "Trojan:BAT/Remcos.MFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {24 61 66 39 32 38 37 30 32 2d 62 65 36 32 2d 34 62 37 66 2d 61 64 33 37 2d 31 35 31 64 62 33 32 63 38 34 37 62 } //1 $af928702-be62-4b7f-ad37-151db32c847b
		$a_81_1 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_81_2 = {70 6f 77 65 72 73 68 65 6c 6c } //1 powershell
		$a_81_3 = {45 6e 63 6f 64 69 6e 67 } //1 Encoding
		$a_81_4 = {47 65 74 53 74 72 69 6e 67 } //1 GetString
		$a_00_5 = {57 95 02 20 09 0a 00 00 00 fa 01 33 00 16 00 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}