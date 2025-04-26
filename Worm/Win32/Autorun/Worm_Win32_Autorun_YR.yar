
rule Worm_Win32_Autorun_YR{
	meta:
		description = "Worm:Win32/Autorun.YR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {83 bd 5c fe ff ff 02 0f 94 c1 f7 d9 66 85 c9 0f 84 } //1
		$a_01_1 = {46 75 63 6b 41 6c 6c 00 46 75 63 6b 45 78 65 00 } //1 畆正汁l畆正硅e
		$a_00_2 = {61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 } //1 autorun.inf
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}