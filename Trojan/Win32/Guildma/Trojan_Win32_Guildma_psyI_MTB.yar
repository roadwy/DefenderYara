
rule Trojan_Win32_Guildma_psyI_MTB{
	meta:
		description = "Trojan:Win32/Guildma.psyI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 e0 21 bc 35 4a 95 33 2f 8d 4f 0e 2e 72 f6 8a 11 8c 15 c8 11 cc c8 93 ?? fc dc fa 8c 88 97 4c 48 97 0c cf 73 6a b6 55 72 d7 } //7
	condition:
		((#a_03_0  & 1)*7) >=7
 
}