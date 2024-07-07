
rule TrojanSpy_Win32_Swisyn_E{
	meta:
		description = "TrojanSpy:Win32/Swisyn.E,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_01_0 = {b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56 0f 94 45 ff } //3
		$a_03_1 = {83 c0 f8 83 f8 66 0f 87 90 01 02 00 00 0f b6 80 90 01 04 ff 24 85 90 00 } //3
		$a_01_2 = {64 72 69 76 65 72 73 2e 6c 6f 67 } //1 drivers.log
		$a_01_3 = {5b 44 65 6c 5d } //1 [Del]
		$a_01_4 = {5b 42 61 63 6b 73 70 61 63 65 5d } //1 [Backspace]
		$a_01_5 = {7b 53 69 6c 7d } //1 {Sil}
		$a_01_6 = {7b 41 72 72 6f 77 5f 55 70 7d } //1 {Arrow_Up}
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=10
 
}