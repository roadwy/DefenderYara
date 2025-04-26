
rule TrojanDropper_Win32_Maener_A{
	meta:
		description = "TrojanDropper:Win32/Maener.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 4d 69 6e 69 6e 67 5f 66 72 61 6d 65 77 6f 72 6b 5c } //2 \Mining_framework\
		$a_01_1 = {00 52 61 75 6d 20 45 78 74 72 61 63 74 } //2
		$a_01_2 = {00 5c 69 6e 74 65 6c 2e 65 78 65 } //1
		$a_01_3 = {6f 72 69 67 69 6e 61 6c 5f 65 78 65 5f 6c 6f 6c } //1 original_exe_lol
		$a_01_4 = {8b c3 c1 e8 10 88 06 8b c3 c1 e8 08 88 46 01 88 5e 02 83 c6 03 bb 01 00 00 00 } //5
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*5) >=7
 
}