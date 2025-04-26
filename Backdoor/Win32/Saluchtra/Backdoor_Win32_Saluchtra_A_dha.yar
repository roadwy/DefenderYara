
rule Backdoor_Win32_Saluchtra_A_dha{
	meta:
		description = "Backdoor:Win32/Saluchtra.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {43 3a 5c 55 73 65 72 73 5c 54 72 61 6e 63 68 75 6c 61 73 5c } //1 C:\Users\Tranchulas\
		$a_03_1 = {2f 66 65 74 63 68 5f 75 70 64 61 74 65 73 5f [0-08] 2e 70 68 70 3f 63 6f 6d 70 6e 61 6d 65 3d } //1
		$a_00_2 = {45 78 70 65 63 74 3a 00 43 4f 4d 50 55 54 45 52 4e 41 4d 45 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}