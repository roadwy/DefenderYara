
rule Trojan_Win32_Guildma_psyQ_MTB{
	meta:
		description = "Trojan:Win32/Guildma.psyQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec b9 d4 04 00 00 6a 00 6a 00 49 75 f9 51 53 56 57 b8 38 ee 14 13 e8 6f 67 ff ff 33 c0 55 68 ce ff 15 13 64 ff 30 64 89 20 33 c0 55 68 26 fe 15 13 64 ff 30 64 89 20 8d 55 e4 33 c0 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}