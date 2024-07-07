
rule TrojanDropper_Win32_Exnuth_A{
	meta:
		description = "TrojanDropper:Win32/Exnuth.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {f6 10 40 39 d8 75 f3 90 09 06 00 80 28 90 01 01 80 30 90 00 } //1
		$a_01_1 = {b8 6f 70 65 6e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}