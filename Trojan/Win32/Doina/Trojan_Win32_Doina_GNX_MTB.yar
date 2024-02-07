
rule Trojan_Win32_Doina_GNX_MTB{
	meta:
		description = "Trojan:Win32/Doina.GNX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {89 f3 f6 d9 28 e1 03 75 00 66 0f b6 ca 8a 46 ff a8 3f 66 81 f1 b7 4b 66 0f be cb } //0a 00 
		$a_01_1 = {30 d8 66 0f be d0 fe ca 0f 94 c6 88 14 24 fe c8 } //01 00 
		$a_01_2 = {50 2e 76 6d 70 30 } //01 00  P.vmp0
		$a_01_3 = {6e 62 62 66 6d 45 58 } //00 00  nbbfmEX
	condition:
		any of ($a_*)
 
}