
rule Trojan_Win64_CobaltStrike_CCJB_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCJB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 8d 6c 24 4c 48 89 cd 41 89 d4 b9 40 00 00 00 ba 0b 00 00 00 48 89 ef ff 15 ?? ?? ?? ?? 44 8b 44 24 3c c7 44 24 28 00 00 00 00 48 8d 15 ?? ?? ?? ?? 48 89 c3 c7 44 24 20 00 00 00 00 48 89 c1 48 89 de 45 0f be c8 45 0f b6 c4 e8 ?? ?? ?? ?? 4d 89 e9 48 89 e9 ba 0b 00 00 00 4c 8b 25 ?? ?? ?? ?? 41 b8 40 00 00 00 41 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}