
rule Trojan_Win32_Guildma_psyU_MTB{
	meta:
		description = "Trojan:Win32/Guildma.psyU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {75 08 5f 33 c0 5e 40 5b c9 c3 56 50 ff 15 24 20 40 00 ff 75 f0 8b 3d 18 20 40 00 89 45 e4 ff d7 8b 4d e4 8d 44 41 04 50 6a 08 ff 75 f4 ff d3 89 45 ec 3b c6 0f 84 42 ff ff ff } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}