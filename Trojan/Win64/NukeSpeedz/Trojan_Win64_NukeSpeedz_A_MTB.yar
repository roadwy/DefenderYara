
rule Trojan_Win64_NukeSpeedz_A_MTB{
	meta:
		description = "Trojan:Win64/NukeSpeedz.A!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6d 79 2d 7f d2 79 75 21 d2 54 07 7f d9 9f 38 58 f3 77 41 98 4e f6 e0 b6 83 d4 a8 b3 d8 3b eb ab bc 26 53 d2 59 79 71 19 34 57 5d 62 dd 37 b7 e1 a4 4c 3b 35 d9 88 c9 d5 4c a4 3e a9 4b 32 26 fc 6d 5c a9 5f da d4 4b f2 01 5c 4f b3 64 a7 ad ea f2 9d af 8b 26 5e ef c9 d4 7d 34 d1 4e f7 e9 bc 92 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}