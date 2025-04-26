
rule Worm_Win32_Autorun_AFV{
	meta:
		description = "Worm:Win32/Autorun.AFV,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {7b 68 69 66 61 67 67 6f 74 7d } //1 {hifaggot}
		$a_01_1 = {46 6c 6f 6f 64 69 6e 67 20 64 6f 6e 65 2e } //1 Flooding done.
		$a_01_2 = {53 74 61 72 74 20 66 6c 6f 6f 64 69 6e 67 2e } //1 Start flooding.
		$a_01_3 = {46 61 69 6c 20 45 72 72 30 72 2e 2e } //1 Fail Err0r..
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}