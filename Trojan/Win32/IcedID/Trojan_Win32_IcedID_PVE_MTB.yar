
rule Trojan_Win32_IcedID_PVE_MTB{
	meta:
		description = "Trojan:Win32/IcedID.PVE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {66 03 de 66 89 15 90 01 04 8b 74 24 18 66 89 1d 90 01 04 8b 1d 90 01 04 81 c3 ac f5 ff ff 89 06 90 09 05 00 a3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}