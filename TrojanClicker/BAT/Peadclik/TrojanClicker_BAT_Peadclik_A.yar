
rule TrojanClicker_BAT_Peadclik_A{
	meta:
		description = "TrojanClicker:BAT/Peadclik.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 61 00 64 00 66 00 2e 00 6c 00 79 00 2f 00 } //1 http://adf.ly/
		$a_01_1 = {47 00 65 00 74 00 6b 00 69 00 6c 00 6c 00 65 00 64 00 } //1 Getkilled
		$a_01_2 = {2f 00 70 00 6c 00 61 00 74 00 66 00 6f 00 72 00 6d 00 3a 00 78 00 38 00 36 00 20 00 2f 00 74 00 61 00 72 00 67 00 65 00 74 00 3a 00 77 00 69 00 6e 00 65 00 78 00 65 00 } //1 /platform:x86 /target:winexe
		$a_01_3 = {43 6c 69 63 6b 4c 69 6e 6b 73 } //1 ClickLinks
		$a_01_4 = {41 64 64 53 74 61 72 74 75 70 } //1 AddStartup
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}