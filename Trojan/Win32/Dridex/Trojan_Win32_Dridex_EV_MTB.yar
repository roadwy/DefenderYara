
rule Trojan_Win32_Dridex_EV_MTB{
	meta:
		description = "Trojan:Win32/Dridex.EV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 44 24 10 8a d1 83 c0 04 02 d2 03 c6 66 a3 ?? ?? ?? ?? b0 2d 2a c2 ba 30 0e 00 00 02 d8 } //10
		$a_02_1 = {0f b7 c6 2b d0 83 c2 16 0f af d0 8b 07 69 d2 81 ea 00 00 89 15 ?? ?? ?? ?? 05 10 b3 07 01 89 07 83 c7 04 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Dridex_EV_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.EV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_81_0 = {46 50 4f 4c 4d 2e 70 64 62 } //3 FPOLM.pdb
		$a_81_1 = {52 70 63 53 74 72 69 6e 67 42 69 6e 64 69 6e 67 50 61 72 73 65 57 } //3 RpcStringBindingParseW
		$a_81_2 = {65 6c 66 20 45 58 } //3 elf EX
		$a_81_3 = {45 53 54 41 50 50 20 45 5f } //3 ESTAPP E_
		$a_81_4 = {31 5a 4d 6f 64 75 6c 65 2c 6d 65 63 68 61 6e 69 73 6d 73 31 53 62 63 39 57 } //3 1ZModule,mechanisms1Sbc9W
		$a_81_5 = {52 61 6e 61 46 63 72 69 6e 74 4d 41 66 68 61 76 65 6c 64 } //3 RanaFcrintMAfhaveld
		$a_81_6 = {7a 69 6a 72 65 63 6f 6d 6d 65 6e 64 65 64 77 68 69 63 68 68 69 73 74 6f 72 79 69 43 79 } //3 zijrecommendedwhichhistoryiCy
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3) >=21
 
}