
rule Trojan_Win64_CobaltStrike_AM_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 63 45 e4 48 3b 45 f0 0f 83 90 01 04 48 8d 05 90 01 04 b9 90 01 04 48 8d 15 90 01 04 4c 63 45 e4 46 0f b6 0c 02 44 8b 55 e4 48 89 45 b8 44 89 d0 99 90 00 } //01 00 
		$a_03_1 = {f7 f9 4c 63 c2 4c 8b 5d b8 43 0f be 0c 03 41 31 c9 44 88 cb 4c 8b 45 e8 48 63 75 e4 41 88 1c 30 8b 45 e4 83 c0 01 89 45 e4 e9 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}