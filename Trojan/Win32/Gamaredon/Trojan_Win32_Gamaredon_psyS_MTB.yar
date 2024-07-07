
rule Trojan_Win32_Gamaredon_psyS_MTB{
	meta:
		description = "Trojan:Win32/Gamaredon.psyS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {8e 9b 4f 92 72 da 23 30 2b 3d ac ce 84 ad f4 98 6d bb 4f 94 81 cb 72 09 67 7b e6 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}