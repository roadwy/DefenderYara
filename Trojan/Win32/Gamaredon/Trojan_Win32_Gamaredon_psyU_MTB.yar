
rule Trojan_Win32_Gamaredon_psyU_MTB{
	meta:
		description = "Trojan:Win32/Gamaredon.psyU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 d2 8d 45 f4 64 8b 0a 64 89 02 89 08 c7 40 04 a8 47 40 00 89 68 08 a3 3c b6 4e 00 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}