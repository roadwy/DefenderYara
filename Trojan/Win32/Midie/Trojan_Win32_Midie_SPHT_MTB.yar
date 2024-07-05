
rule Trojan_Win32_Midie_SPHT_MTB{
	meta:
		description = "Trojan:Win32/Midie.SPHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 68 81 71 02 00 6a 00 ff 90 } //00 00 
	condition:
		any of ($a_*)
 
}