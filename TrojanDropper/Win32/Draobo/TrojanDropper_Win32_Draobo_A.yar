
rule TrojanDropper_Win32_Draobo_A{
	meta:
		description = "TrojanDropper:Win32/Draobo.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {25 00 73 00 2e 00 2e 00 5c 00 25 00 58 00 2e 00 64 00 6c 00 6c 00 } //1 %s..\%X.dll
		$a_03_1 = {8b 4c 3a 24 8b 44 3a 20 03 cf 89 4c 24 14 8b 4c 3a 18 55 03 c7 33 ed 85 c9 89 44 24 14 76 90 01 01 eb 04 8b 44 24 14 8b 0c a8 8b 74 24 24 03 cf 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}