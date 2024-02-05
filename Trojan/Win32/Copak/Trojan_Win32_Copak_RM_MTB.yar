
rule Trojan_Win32_Copak_RM_MTB{
	meta:
		description = "Trojan:Win32/Copak.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {21 d2 09 c9 b9 8f ff 92 9a 01 00 00 75 05 bb 00 00 00 00 40 89 c0 c3 } //00 00 
	condition:
		any of ($a_*)
 
}