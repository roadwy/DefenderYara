
rule Trojan_Win64_Rootkit_SX_MTB{
	meta:
		description = "Trojan:Win64/Rootkit.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_03_0 = {42 0f b7 44 4f ?? 0f b7 f0 0f b7 c8 66 c1 e8 0c 66 83 f8 0a 75 ?? 49 23 f3 4c 01 04 16 eb } //20
		$a_03_1 = {0f b7 c6 0f b7 fe 48 8d 14 80 0f b7 c1 45 8b 4c d4 ?? 41 2b c6 3b f8 75 ?? 8b 7b 50 eb } //10
		$a_03_2 = {41 0f b7 c0 66 45 03 c1 48 8d 14 80 41 8b 74 d4 ?? 41 8b 7c d4 ?? 49 03 f6 41 8b 4c d4 ?? 48 03 fd f3 a4 66 44 3b 43 } //5
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10+(#a_03_2  & 1)*5) >=35
 
}