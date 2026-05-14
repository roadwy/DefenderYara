
rule Trojan_Win64_KillMBR_SX_MTB{
	meta:
		description = "Trojan:Win64/KillMBR.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {c1 e8 0b 41 0f af c8 c1 e9 08 0a c8 41 8b c0 c1 e8 09 22 c8 41 0f be c0 80 e1 12 0f be d1 b9 40 00 00 00 0f af d0 41 8b c0 c1 e8 04 2a c8 41 8b c0 41 ff c0 0a d1 } //20
		$a_01_1 = {45 03 c0 b8 01 01 00 00 41 f7 e0 41 8b c0 2b c2 d1 e8 03 c2 c1 e8 17 69 c0 ff ff ff 00 44 2b c0 45 89 01 3b cb 7c } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}