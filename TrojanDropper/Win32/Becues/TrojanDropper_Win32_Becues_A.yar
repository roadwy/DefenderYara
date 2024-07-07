
rule TrojanDropper_Win32_Becues_A{
	meta:
		description = "TrojanDropper:Win32/Becues.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {74 4c 33 f6 3b c3 76 0d 8a 4c 35 e0 30 4c 35 ec 46 3b f0 72 f3 6a 01 53 f7 d8 50 ff 75 f8 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}