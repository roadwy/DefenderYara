
rule Trojan_BAT_Formbook_AOK_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AOK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 1c 12 10 28 ?? ?? ?? 0a 0d 2b 12 12 10 28 ?? ?? ?? 0a 0d 2b 08 12 10 28 ?? ?? ?? 0a 0d 11 05 09 6f ?? ?? ?? 0a 08 17 58 0c 08 11 07 fe 04 13 0c 11 0c 2d a4 07 17 58 0b 07 11 08 fe 04 13 0d 11 0d 2d 91 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Formbook_AOK_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.AOK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0a 0a 06 72 ed 05 00 70 28 10 00 00 06 6f 40 00 00 0a 00 06 18 6f 41 00 00 0a 00 06 18 6f 42 00 00 0a 00 06 6f 43 00 00 0a 0b 07 02 16 02 8e 69 6f 44 00 00 0a 0c 2b 00 } //2
		$a_01_1 = {66 00 6f 00 72 00 6d 00 75 00 6c 00 61 00 72 00 69 00 6f 00 31 00 35 00 31 00 31 00 32 00 32 00 2e 00 65 00 78 00 65 00 } //1 formulario151122.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}