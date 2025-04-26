
rule TrojanDropper_Win32_Glaze_C{
	meta:
		description = "TrojanDropper:Win32/Glaze.C,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 02 5f c6 06 4d 39 7d f4 c6 46 01 5a 76 25 89 5d f8 29 75 f8 8b c7 6a 09 99 5b 8d 0c 37 f7 fb 8a c2 b2 03 f6 ea 8b 55 f8 32 04 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}