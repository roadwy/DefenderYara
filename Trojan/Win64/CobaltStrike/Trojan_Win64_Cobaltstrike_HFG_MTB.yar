
rule Trojan_Win64_Cobaltstrike_HFG_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.HFG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b6 c1 2a c3 24 c0 41 32 c0 30 01 48 03 ce 49 3b ca } //00 00 
	condition:
		any of ($a_*)
 
}