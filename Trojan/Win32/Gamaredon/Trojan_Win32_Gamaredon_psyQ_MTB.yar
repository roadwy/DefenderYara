
rule Trojan_Win32_Gamaredon_psyQ_MTB{
	meta:
		description = "Trojan:Win32/Gamaredon.psyQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {50 30 20 00 58 d8 90 00 54 84 54 00 c4 90 58 00 00 c4 2c 00 24 d4 5c 00 9c 8c 84 00 60 5c 58 00 4c b0 54 00 e0 e0 d8 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}