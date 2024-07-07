
rule Trojan_Win32_Gamaredon_psyM_MTB{
	meta:
		description = "Trojan:Win32/Gamaredon.psyM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {be 00 10 40 00 89 f7 bb 09 00 00 00 64 8b 15 30 00 00 00 52 6a 00 b9 4c 03 00 00 8a 06 28 d8 aa 46 e2 f8 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}