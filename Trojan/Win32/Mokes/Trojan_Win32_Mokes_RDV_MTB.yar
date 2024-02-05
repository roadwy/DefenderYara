
rule Trojan_Win32_Mokes_RDV_MTB{
	meta:
		description = "Trojan:Win32/Mokes.RDV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 ff 3b de 7e 90 01 01 8b 45 90 01 01 8d 0c 07 e8 90 01 04 30 01 83 fb 19 75 90 01 01 56 56 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}