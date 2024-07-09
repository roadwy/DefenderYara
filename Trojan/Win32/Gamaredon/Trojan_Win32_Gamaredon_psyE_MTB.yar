
rule Trojan_Win32_Gamaredon_psyE_MTB{
	meta:
		description = "Trojan:Win32/Gamaredon.psyE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_03_0 = {f3 a5 33 c9 33 c0 66 a5 [0-07] 8b d1 74 09 40 41 3d 00 e1 f5 05 7c ef 8d 45 f4 50 6a 40 52 53 } //7
	condition:
		((#a_03_0  & 1)*7) >=7
 
}