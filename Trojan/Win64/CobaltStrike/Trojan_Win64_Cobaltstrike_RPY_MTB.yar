
rule Trojan_Win64_Cobaltstrike_RPY_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 8b 0d 3b 10 00 00 ba 05 00 00 00 80 34 3e 05 ff 15 24 10 00 00 48 ff c6 48 81 fe 7b 03 00 00 72 c0 } //00 00 
	condition:
		any of ($a_*)
 
}