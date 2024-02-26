
rule Trojan_Win32_Lazy_AMBA_MTB{
	meta:
		description = "Trojan:Win32/Lazy.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b 64 69 63 7a 79 6c 67 72 61 67 65 67 65 61 7a 72 6b 74 74 6a 74 64 75 79 63 6e } //01 00  kdiczylgragegeazrkttjtduycn
		$a_01_1 = {6e 6a 76 6e 75 76 76 73 67 63 63 64 66 74 74 7a 72 70 74 } //01 00  njvnuvvsgccdfttzrpt
		$a_01_2 = {71 74 70 6a 6b 62 68 70 61 75 6d 74 6a 62 63 6a 79 77 6a 62 6d 61 62 6b 70 68 6e 61 69 74 73 61 6c 6b 6c } //01 00  qtpjkbhpaumtjbcjywjbmabkphnaitsalkl
		$a_01_3 = {64 71 6c 79 78 61 6c 75 74 67 62 76 66 72 79 67 79 67 68 68 74 61 6d 78 71 71 65 69 6a 76 67 6a 65 } //00 00  dqlyxalutgbvfrygyghhtamxqqeijvgje
	condition:
		any of ($a_*)
 
}