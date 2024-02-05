
rule Trojan_Win32_Cutwail_CRUT_MTB{
	meta:
		description = "Trojan:Win32/Cutwail.CRUT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 ee 03 d6 c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 c2 8b c8 c1 e1 90 01 01 2b c8 8b c6 2b c1 46 8a 88 90 01 04 32 8e 90 01 04 8b 45 fc 88 4c 06 ff 3b 75 0c 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}