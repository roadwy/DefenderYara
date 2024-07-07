
rule TrojanDropper_Win32_Lolyda_F{
	meta:
		description = "TrojanDropper:Win32/Lolyda.F,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 b8 d4 07 66 ab 33 c0 66 b8 08 00 66 ab 33 c0 66 b8 08 00 } //1
		$a_01_1 = {83 7d 0c 00 75 1f 8b 7d fc 8b 55 08 8b df 2b d3 83 ea 05 89 55 f8 b0 e9 aa } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}