
rule Trojan_Win32_Artemis_RDA_MTB{
	meta:
		description = "Trojan:Win32/Artemis.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {b8 01 00 00 00 d1 e0 0f be 4c 05 d8 c1 e1 06 ba 01 00 00 00 6b c2 03 0f be 54 05 d8 03 ca 8b 45 d0 03 45 dc 88 08 8b 4d dc 83 c1 01 } //00 00 
	condition:
		any of ($a_*)
 
}