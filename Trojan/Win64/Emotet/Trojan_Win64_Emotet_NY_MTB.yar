
rule Trojan_Win64_Emotet_NY_MTB{
	meta:
		description = "Trojan:Win64/Emotet.NY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 f9 48 63 ca 48 8b 05 90 01 04 0f b6 04 08 41 8b d0 33 d0 8b 0d 90 00 } //01 00 
		$a_03_1 = {2b c1 48 63 c8 48 8b 84 24 90 01 04 88 14 08 e9 90 00 } //01 00 
		$a_01_2 = {5e 5e 30 73 6b 25 48 73 6c 2b 43 69 4a 4c 6f 5e 39 45 55 66 52 4c 7a 58 4a 28 44 58 4e 53 67 6b 70 6d 6b 4d 37 4d 2b } //00 00  ^^0sk%Hsl+CiJLo^9EUfRLzXJ(DXNSgkpmkM7M+
	condition:
		any of ($a_*)
 
}