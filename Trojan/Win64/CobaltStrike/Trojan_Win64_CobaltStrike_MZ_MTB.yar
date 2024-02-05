
rule Trojan_Win64_CobaltStrike_MZ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {31 f6 4c 89 c7 49 89 cc 49 89 d7 44 89 cb 48 8d ac 24 20 01 00 00 4c 8d 74 24 60 49 89 ed 4c 8d 44 24 48 49 8b 04 37 49 8d 0c 30 4c 89 f2 4c 89 44 24 28 48 83 c6 08 4a 89 44 06 f8 } //05 00 
		$a_01_1 = {41 89 c8 31 c9 45 0f be c0 44 89 c0 d3 f8 83 e0 01 88 04 0a 48 ff c1 48 83 f9 08 75 ec } //00 00 
	condition:
		any of ($a_*)
 
}