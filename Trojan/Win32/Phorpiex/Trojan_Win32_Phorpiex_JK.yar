
rule Trojan_Win32_Phorpiex_JK{
	meta:
		description = "Trojan:Win32/Phorpiex.JK,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e5 a0 f3 e2 a1 c1 9d b1 a1 c1 9d b1 a1 c1 9d b1 32 8f 05 b1 a3 c1 9d b1 ba 5c 03 b1 8d c1 9d b1 ba 5c 36 b1 9c c1 9d b1 ba 5c 37 b1 2d c1 9d b1 a8 b9 0e b1 80 c1 9d b1 a1 c1 9c b1 8e c0 9d b1 ba 5c 32 b1 89 c1 9d b1 ba 5c 07 b1 a0 c1 9d b1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}