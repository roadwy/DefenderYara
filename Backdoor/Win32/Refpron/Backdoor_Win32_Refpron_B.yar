
rule Backdoor_Win32_Refpron_B{
	meta:
		description = "Backdoor:Win32/Refpron.B,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_01_0 = {32 cb 88 4c 10 ff 0f b7 45 f2 8b 55 fc 0f b6 44 02 ff 66 03 45 f0 66 69 c0 6d ce 66 05 bf 58 66 89 45 f0 66 ff 45 f2 66 ff 4d ee } //10
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_00_2 = {65 5f 72 5f 72 5f 6f 5f 72 } //1 e_r_r_o_r
		$a_00_3 = {4f 70 65 6e 20 20 20 46 69 6c 65 20 20 20 45 72 72 6f 72 } //1 Open   File   Error
		$a_00_4 = {54 4d 79 5f 4d 5f 69 5f 6e 69 54 5f 43 5f 50 43 5f 6c 69 65 6e 74 } //1 TMy_M_i_niT_C_PC_lient
	condition:
		((#a_01_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=21
 
}