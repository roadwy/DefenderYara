
rule Trojan_Win32_Gamaredon_psyV_MTB{
	meta:
		description = "Trojan:Win32/Gamaredon.psyV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {53 00 63 00 72 00 69 00 70 00 74 00 20 00 50 } //00 00 
	condition:
		any of ($a_*)
 
}