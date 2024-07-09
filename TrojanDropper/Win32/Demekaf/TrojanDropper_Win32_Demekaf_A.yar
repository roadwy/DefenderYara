
rule TrojanDropper_Win32_Demekaf_A{
	meta:
		description = "TrojanDropper:Win32/Demekaf.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 3f 7a 75 09 80 7f 01 5a 75 03 c6 07 4d } //1
		$a_03_1 = {b9 2b 02 00 00 33 c0 8d 7c 24 ?? f3 ab } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}