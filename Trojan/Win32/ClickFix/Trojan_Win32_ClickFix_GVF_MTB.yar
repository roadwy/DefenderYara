
rule Trojan_Win32_ClickFix_GVF_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.GVF!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,ffffff8d 00 ffffff8d 00 04 00 00 "
		
	strings :
		$a_00_0 = {2e 00 78 00 79 00 7a 00 } //100 .xyz
		$a_00_1 = {2e 00 72 00 65 00 70 00 4c 00 61 00 43 00 45 00 28 00 28 00 5b 00 43 00 68 00 41 00 72 00 5d 00 } //40 .repLaCE(([ChAr]
		$a_00_2 = {6a 00 4f 00 69 00 4e 00 } //1 jOiN
		$a_00_3 = {43 00 6c 00 6f 00 75 00 64 00 } //-100 Cloud
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*40+(#a_00_2  & 1)*1+(#a_00_3  & 1)*-100) >=141
 
}