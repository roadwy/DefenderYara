
rule Trojan_Win32_Multsarch_Q{
	meta:
		description = "Trojan:Win32/Multsarch.Q,SIGNATURE_TYPE_PEHSTR,03 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 50 ff b3 f4 00 00 00 ff b3 f0 00 00 00 51 8b d3 8b 8b cc 00 00 00 8b 43 5c ff 53 58 } //1
		$a_01_1 = {73 00 6f 00 66 00 74 00 5f 00 73 00 65 00 61 00 72 00 63 00 68 00 2e 00 70 00 68 00 70 00 3f 00 63 00 6f 00 64 00 65 00 3d 00 } //1 soft_search.php?code=
		$a_01_2 = {43 00 65 00 6c 00 6c 00 2c 00 20 00 41 00 63 00 74 00 69 00 56 00 2c 00 20 00 42 00 65 00 65 00 6c 00 69 00 6e 00 65 00 2c 00 20 00 4e 00 45 00 4f 00 2c 00 20 00 44 00 61 00 6c 00 61 00 63 00 6f 00 6d 00 2c 00 20 00 50 00 61 00 74 00 68 00 77 00 6f 00 72 00 64 00 2e 00 20 00 } //1 Cell, ActiV, Beeline, NEO, Dalacom, Pathword. 
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}