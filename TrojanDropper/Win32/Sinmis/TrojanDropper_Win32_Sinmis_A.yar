
rule TrojanDropper_Win32_Sinmis_A{
	meta:
		description = "TrojanDropper:Win32/Sinmis.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 0c 3a 32 0c 2e 83 c6 01 88 0a 83 c2 01 80 3c 2e 00 75 02 33 f6 } //1
		$a_01_1 = {80 c2 61 88 14 3e 83 c6 01 3b f5 7c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}