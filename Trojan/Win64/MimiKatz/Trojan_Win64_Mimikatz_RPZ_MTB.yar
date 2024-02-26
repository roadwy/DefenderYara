
rule Trojan_Win64_Mimikatz_RPZ_MTB{
	meta:
		description = "Trojan:Win64/Mimikatz.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 89 c6 48 89 7c 24 40 48 89 74 24 48 48 63 70 3c 8b 54 30 50 31 c9 41 b8 00 30 00 00 41 b9 04 00 00 00 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}