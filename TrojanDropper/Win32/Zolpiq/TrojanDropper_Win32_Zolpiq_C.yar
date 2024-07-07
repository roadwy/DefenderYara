
rule TrojanDropper_Win32_Zolpiq_C{
	meta:
		description = "TrojanDropper:Win32/Zolpiq.C,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 c2 7f 30 10 41 81 f9 00 40 9c 00 7c eb } //1
		$a_01_1 = {03 f8 8b 86 10 01 00 00 03 c3 2b b8 0c 01 00 00 05 08 01 00 00 2b be 0c 01 00 00 47 39 38 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}