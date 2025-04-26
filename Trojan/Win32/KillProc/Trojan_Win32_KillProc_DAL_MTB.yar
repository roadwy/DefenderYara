
rule Trojan_Win32_KillProc_DAL_MTB{
	meta:
		description = "Trojan:Win32/KillProc.DAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {2a ea ba 49 e9 c6 a0 9e 40 d2 1a ce d2 cf 2b 22 25 4a 1f 2e ad 18 48 d0 33 36 1b a6 bf 84 fb e7 f9 02 fc 0c ec 7e } //2
		$a_01_1 = {5c ae 52 36 a6 49 31 d8 d6 8e 16 15 d5 f1 b5 74 01 a1 8b 54 80 cc 82 de b5 be aa 05 73 c3 af 50 fa 74 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}