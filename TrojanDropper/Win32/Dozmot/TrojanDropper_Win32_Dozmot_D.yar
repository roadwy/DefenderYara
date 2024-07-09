
rule TrojanDropper_Win32_Dozmot_D{
	meta:
		description = "TrojanDropper:Win32/Dozmot.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 7d f4 00 10 40 00 0f 85 ?? ?? ?? ?? 6a 02 6a 00 6a f8 } //1
		$a_03_1 = {8b ce 83 ee 08 d3 ea 48 89 75 ?? 88 90 90 ?? ?? ?? ?? 79 e7 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}