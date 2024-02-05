
rule Trojan_Win32_Copak_CS_MTB{
	meta:
		description = "Trojan:Win32/Copak.CS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {31 30 29 ff 89 ff 40 81 c1 90 02 04 89 cf 39 d0 75 d3 90 00 } //02 00 
		$a_03_1 = {31 3a 01 cb 81 eb 90 02 04 42 89 d9 39 c2 75 d7 90 00 } //02 00 
		$a_01_2 = {01 d2 31 0b 43 29 c0 89 c0 39 fb 75 e6 } //00 00 
	condition:
		any of ($a_*)
 
}