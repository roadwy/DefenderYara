
rule TrojanSpy_BAT_Hoetou_B{
	meta:
		description = "TrojanSpy:BAT/Hoetou.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6b 79 6c 00 4d 6f 64 75 6c 65 } //1 祫l潍畤敬
		$a_01_1 = {55 52 4c 46 69 6c 65 00 44 6f 77 6e 6c 6f 61 64 65 64 46 69 6c 65 } //1 剕䙌汩e潄湷潬摡摥楆敬
		$a_01_2 = {53 63 72 65 65 6e 78 00 } //1 捓敲湥x
		$a_01_3 = {42 79 74 65 73 63 6f 75 74 53 63 72 65 65 6e 43 61 70 74 75 72 69 6e 67 4c 69 62 } //1 BytescoutScreenCapturingLib
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}