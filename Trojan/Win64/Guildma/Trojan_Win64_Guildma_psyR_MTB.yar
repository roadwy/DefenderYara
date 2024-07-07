
rule Trojan_Win64_Guildma_psyR_MTB{
	meta:
		description = "Trojan:Win64/Guildma.psyR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {15 25 00 48 00 6f 00 6d 00 65 00 50 00 61 00 74 00 68 00 25 00 00 15 25 00 48 00 4f 00 4d 00 45 00 50 00 41 00 54 00 48 00 25 00 00 0d 50 00 55 00 42 00 4c 00 49 00 43 00 00 11 25 00 50 00 75 00 62 00 6c 00 69 00 63 00 25 00 00 11 25 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}