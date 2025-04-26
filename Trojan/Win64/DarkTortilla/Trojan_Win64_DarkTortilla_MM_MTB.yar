
rule Trojan_Win64_DarkTortilla_MM_MTB{
	meta:
		description = "Trojan:Win64/DarkTortilla.MM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {53 65 6e 64 45 66 66 65 63 74 69 76 65 6c 79 } //SendEffectively  3
		$a_00_1 = {66 72 6f 6e 74 74 65 63 68 6e 6f 6c 6f 67 69 63 61 6c 2e 65 78 65 } //1 fronttechnological.exe
		$a_00_2 = {57 65 78 74 72 61 63 74 } //1 Wextract
		$a_00_3 = {49 58 50 30 30 30 2e 54 4d 50 } //1 IXP000.TMP
	condition:
		((#a_80_0  & 1)*3+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}