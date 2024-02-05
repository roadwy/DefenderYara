
rule Trojan_Win32_Emotet_PVE_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PVE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {b9 7d 03 00 00 f7 f9 8b 44 24 18 8b 4c 24 24 40 89 44 24 18 8a 54 14 28 30 54 01 ff 83 bc 24 90 01 04 00 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}