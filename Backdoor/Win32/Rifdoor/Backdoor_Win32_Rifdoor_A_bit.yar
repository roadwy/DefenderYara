
rule Backdoor_Win32_Rifdoor_A_bit{
	meta:
		description = "Backdoor:Win32/Rifdoor.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b c8 80 30 0f 41 8b c1 38 19 75 f6 } //1
		$a_01_1 = {54 72 6f 79 20 53 6f 75 72 63 65 20 43 6f 64 65 5c 74 63 70 31 73 74 5c 72 69 66 6c 65 5c 52 65 6c 65 61 73 65 5c 72 69 66 6c 65 2e 70 64 62 } //1 Troy Source Code\tcp1st\rifle\Release\rifle.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}