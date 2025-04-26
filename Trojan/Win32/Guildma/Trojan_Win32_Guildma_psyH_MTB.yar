
rule Trojan_Win32_Guildma_psyH_MTB{
	meta:
		description = "Trojan:Win32/Guildma.psyH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_03_0 = {57 c6 04 24 09 89 24 24 8b 6d 00 66 c7 04 24 ef be 68 b1 f1 f0 de 60 8d 64 24 28 e9 27 ff ff ff 68 e0 c7 50 39 80 fc ?? ?? ?? 24 83 c5 06 60 ?? ?? ?? ?? ?? 81 ee 96 a1 51 ef } //7
	condition:
		((#a_03_0  & 1)*7) >=7
 
}