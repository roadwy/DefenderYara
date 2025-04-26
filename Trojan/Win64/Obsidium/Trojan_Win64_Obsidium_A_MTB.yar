
rule Trojan_Win64_Obsidium_A_MTB{
	meta:
		description = "Trojan:Win64/Obsidium.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 b3 d5 98 cd eb 02 30 14 35 c2 55 9f 4d 73 03 a0 b7 aa 41 f7 e0 eb 03 25 59 3a b8 34 8b 34 d2 eb 02 83 38 35 45 0b 33 52 71 01 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}