
rule Trojan_Win64_Prowloc_RPW_MTB{
	meta:
		description = "Trojan:Win64/Prowloc.RPW!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f be 54 04 20 83 ea 09 88 54 04 20 48 ff c0 48 83 f8 09 72 eb } //00 00 
	condition:
		any of ($a_*)
 
}