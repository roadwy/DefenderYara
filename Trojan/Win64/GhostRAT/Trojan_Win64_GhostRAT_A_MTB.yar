
rule Trojan_Win64_GhostRAT_A_MTB{
	meta:
		description = "Trojan:Win64/GhostRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 8b c1 41 83 c3 ?? 48 c1 e8 ?? 48 ff c2 8a 04 28 41 88 02 48 8b c1 48 c1 e8 } //2
		$a_01_1 = {25 73 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //2 %s\shell\open\command
		$a_01_2 = {25 2d 32 34 73 20 25 2d 31 35 73 } //2 %-24s %-15s
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}