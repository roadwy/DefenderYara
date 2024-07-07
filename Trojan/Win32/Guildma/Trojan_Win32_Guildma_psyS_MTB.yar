
rule Trojan_Win32_Guildma_psyS_MTB{
	meta:
		description = "Trojan:Win32/Guildma.psyS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec b9 07 00 00 00 6a 00 6a 00 49 75 f9 53 56 b8 f8 8f 41 00 e8 59 d3 fe ff 33 c0 55 68 b5 92 41 00 64 ff 30 64 89 20 68 00 01 00 00 68 60 c2 42 00 6a 00 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}