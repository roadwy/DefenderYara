
rule Trojan_Win32_Crysant_RPS_MTB{
	meta:
		description = "Trojan:Win32/Crysant.RPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 00 40 00 04 00 00 00 04 00 00 00 01 c0 85 c0 } //00 00 
	condition:
		any of ($a_*)
 
}