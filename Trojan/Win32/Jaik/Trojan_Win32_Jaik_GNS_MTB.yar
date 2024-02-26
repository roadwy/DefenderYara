
rule Trojan_Win32_Jaik_GNS_MTB{
	meta:
		description = "Trojan:Win32/Jaik.GNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {34 d8 13 0d 90 01 04 31 2b 79 31 f3 5a 8a c4 d0 c3 90 00 } //01 00 
		$a_01_1 = {62 34 76 4e 69 52 37 43 61 } //01 00  b4vNiR7Ca
		$a_01_2 = {50 2e 76 6d 70 30 } //00 00  P.vmp0
	condition:
		any of ($a_*)
 
}