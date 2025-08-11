
rule Trojan_BAT_Malgent_PGM_MTB{
	meta:
		description = "Trojan:BAT/Malgent.PGM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {0f 7b 00 30 00 7d 00 2f 00 7b 00 31 00 7d 00 00 1f 5c 00 73 00 28 00 3f 00 3c 00 6b 00 65 00 79 00 3e 00 2e 00 2a 00 3f 00 29 00 5c 00 2e 00 00 07 6b 00 65 00 79 } //1
		$a_80_1 = {69 6e 66 6f 2d 73 65 63 2e 6a 70 2f 61 74 74 61 63 68 } //info-sec.jp/attach  1
		$a_80_2 = {73 74 67 73 65 63 2d 69 6e 66 6f 2e 6a 70 2f 61 63 6f 6e } //stgsec-info.jp/acon  1
		$a_80_3 = {50 64 66 41 74 74 61 63 68 50 72 6f 64 75 63 74 69 6f 6e 2e 65 78 65 } //PdfAttachProduction.exe  2
	condition:
		((#a_01_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*2) >=5
 
}