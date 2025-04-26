
rule Trojan_Win64_SteelFox_AFO_MTB{
	meta:
		description = "Trojan:Win64/SteelFox.AFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c8 c1 e9 10 0f b6 f8 32 d1 41 c0 f8 07 41 80 e0 1b 40 c0 ff 07 40 80 e7 1b 8b c8 c1 e9 08 8b f0 32 d1 c1 ee 18 41 32 d0 8b d8 40 32 d7 c1 eb 10 88 54 24 70 44 32 db 40 0f b6 d6 45 02 db 40 32 f0 32 d3 02 d2 40 02 f6 44 8b c8 44 8b d0 41 c1 e9 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}