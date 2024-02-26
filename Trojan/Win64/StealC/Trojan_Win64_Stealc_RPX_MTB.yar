
rule Trojan_Win64_Stealc_RPX_MTB{
	meta:
		description = "Trojan:Win64/Stealc.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {00 10 00 00 77 47 00 00 f8 90 01 01 19 00 77 47 00 00 98 47 00 00 1c 90 01 01 19 00 98 47 00 00 b9 47 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}