
rule Trojan_Win32_Foosace_F_dha{
	meta:
		description = "Trojan:Win32/Foosace.F!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 69 76 65 20 25 73 20 6e 6f 74 20 66 6f 75 6e 64 00 } //1
		$a_01_1 = {63 66 73 64 61 74 61 2e 64 61 74 00 } //1
		$a_01_2 = {65 6b 6e 64 61 74 61 2e 64 61 74 00 } //1
		$a_01_3 = {52 65 67 20 70 6c 75 67 69 6e 73 3a } //1 Reg plugins:
		$a_01_4 = {45 72 72 20 6f 70 65 6e 20 6b 65 79 20 25 2e 38 78 2d 25 73 3a 25 2e 38 78 } //1 Err open key %.8x-%s:%.8x
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}