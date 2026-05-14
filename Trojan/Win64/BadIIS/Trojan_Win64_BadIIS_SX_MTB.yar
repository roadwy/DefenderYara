
rule Trojan_Win64_BadIIS_SX_MTB{
	meta:
		description = "Trojan:Win64/BadIIS.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 04 00 00 "
		
	strings :
		$a_03_0 = {48 85 c0 74 ?? 48 8d ?? ?? ?? ?? ?? 48 89 ?? ?? ?? ?? ?? 48 89 ?? 45 33 c9 48 8b ?? 41 b8 01 00 00 00 [0-07] 48 8b cb 48 83 c4 20 } //20
		$a_03_1 = {48 c7 c3 ff ff ff ff 48 89 45 ?? 0f 11 44 24 ?? c7 44 24 ?? 68 00 00 00 48 8b d3 0f 11 44 24 ?? c7 44 24 ?? ff ff ff ff } //10
		$a_80_2 = {78 2d 72 65 61 6c 2d 69 70 3a 20 25 73 } //x-real-ip: %s  3
		$a_01_3 = {5c 53 65 61 72 63 68 45 6e 67 69 6e 65 } //2 \SearchEngine
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10+(#a_80_2  & 1)*3+(#a_01_3  & 1)*2) >=35
 
}