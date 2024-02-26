
rule Trojan_Win32_Injuke_GMD_MTB{
	meta:
		description = "Trojan:Win32/Injuke.GMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {d0 65 e5 00 62 00 00 00 01 00 35 00 13 74 92 67 a3 d2 3e } //01 00 
		$a_80_1 = {50 65 4d 65 6d 6f 72 79 52 75 6e 32 30 2e 65 78 65 } //PeMemoryRun20.exe  00 00 
	condition:
		any of ($a_*)
 
}