
rule Trojan_Win64_IcedID_RDE_MTB{
	meta:
		description = "Trojan:Win64/IcedID.RDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {41 8b 4a 30 41 03 cb 81 f1 0e 16 0a 00 0f af c1 } //00 00 
	condition:
		any of ($a_*)
 
}