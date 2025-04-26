
rule Backdoor_Win32_Botintin_A{
	meta:
		description = "Backdoor:Win32/Botintin.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_01_0 = {5c 50 72 6f 6a 65 63 74 73 5c 49 6e 66 69 6e 69 74 79 20 42 6f 74 5c } //1 \Projects\Infinity Bot\
		$a_01_1 = {2f 50 61 6e 65 6c 2f 69 6e 66 2f 61 63 63 65 70 74 2e 70 68 70 00 } //1
		$a_01_2 = {26 74 61 73 6b 3d } //1 &task=
		$a_01_3 = {26 6f 73 3d } //1 &os=
		$a_01_4 = {26 71 75 61 6c 69 74 79 3d } //1 &quality=
		$a_01_5 = {26 63 6f 6d 70 75 74 65 72 3d } //1 &computer=
		$a_01_6 = {26 63 6f 75 6e 74 72 79 3d } //1 &country=
		$a_03_7 = {3f 68 77 69 64 3d [0-02] 57 69 6e 64 6f 77 73 25 32 30 32 30 30 30 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_03_7  & 1)*1) >=6
 
}