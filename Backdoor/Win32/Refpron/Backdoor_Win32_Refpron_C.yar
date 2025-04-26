
rule Backdoor_Win32_Refpron_C{
	meta:
		description = "Backdoor:Win32/Refpron.C,SIGNATURE_TYPE_PEHSTR,0f 00 0f 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {8a 54 3a ff 0f b7 ce c1 e9 08 32 d1 88 54 38 ff 8b 04 24 0f b6 44 38 ff 66 03 f0 66 69 c6 6d ce 66 05 bf 58 8b f0 43 66 ff 4c 24 04 75 } //2
		$a_01_2 = {8a 54 2a ff 0f b7 cf c1 e9 08 32 d1 88 54 28 ff 8b 06 0f b6 44 28 ff 66 03 f8 66 69 c7 6d ce 66 05 bf 58 8b f8 43 66 ff 0c 24 75 } //2
		$a_01_3 = {65 5f 72 72 6f 5f 72 } //1 e_rro_r
		$a_01_4 = {65 5f 72 72 5f 6f 5f 72 } //1 e_rr_o_r
		$a_01_5 = {4f 70 65 6e 20 20 20 46 69 6c 65 20 20 20 45 72 72 6f 72 21 21 21 } //1 Open   File   Error!!!
		$a_01_6 = {54 4d 79 5f 4d 5f 69 5f 6e 69 54 5f 43 5f 50 43 5f 6c 69 65 6e 74 } //1 TMy_M_i_niT_C_PC_lient
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=15
 
}