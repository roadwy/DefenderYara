
rule Trojan_Win64_CobaltStrike_ZK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ZK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {41 f7 e8 41 03 d0 c1 fa 05 8b c2 c1 e8 1f 03 d0 b8 90 01 04 2a c2 0f be c0 6b c8 90 01 01 41 02 c8 41 ff c0 41 30 09 49 ff c1 41 83 f8 16 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}