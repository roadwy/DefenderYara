
rule Trojan_Win32_Gamaredon_psyK_MTB{
	meta:
		description = "Trojan:Win32/Gamaredon.psyK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff 15 94 66 00 10 a3 8c 66 00 10 8d 4d d0 ba 60 48 00 10 b8 d4 48 00 10 e8 ac d6 ff ff 8b 45 d0 e8 60 d2 ff ff 50 a1 80 66 00 10 50 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}