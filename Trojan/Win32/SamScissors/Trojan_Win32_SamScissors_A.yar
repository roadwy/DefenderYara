
rule Trojan_Win32_SamScissors_A{
	meta:
		description = "Trojan:Win32/SamScissors.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {ce fe ed fa ce 7d 61 d5 99 70 a9 00 4e 8c 29 43 c5 f6 cb 41 6d b2 ee 5e 54 37 71 21 26 50 a1 f1 1f c8 2c 60 b0 ef 05 d4 32 41 5d 95 59 07 9c e7 9b 29 7e 8f 9f 54 57 91 45 33 d4 3d 7d 07 77 01 47 d1 07 49 22 cd fc a2 18 6f 84 0a db f2 e0 25 } //2
		$a_00_1 = {44 33 44 43 4f 4d 50 49 4c 45 52 5f 34 37 2e 64 6c 6c } //2 D3DCOMPILER_47.dll
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*2) >=4
 
}