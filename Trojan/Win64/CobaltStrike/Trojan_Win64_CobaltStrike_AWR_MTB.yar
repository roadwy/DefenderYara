
rule Trojan_Win64_CobaltStrike_AWR_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AWR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c1 48 c1 e9 90 01 01 33 45 8f 33 cf 89 4c 24 2c 66 48 0f 7e c9 89 44 24 28 8b c1 0f 10 44 24 20 48 c1 e9 20 41 33 c7 33 ce 89 44 24 50 89 4c 24 54 66 0f 73 d9 08 66 48 0f 7e c9 8b c1 48 c1 e9 20 41 33 ce 41 33 c4 48 83 6d 67 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}