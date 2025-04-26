
rule TrojanDropper_Win32_Emptybase_A{
	meta:
		description = "TrojanDropper:Win32/Emptybase.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 7d f8 76 18 33 d2 6a 03 8b c1 5e f7 f6 28 91 08 40 40 00 41 3b 0d 04 40 40 00 72 e8 39 1d 00 40 40 00 89 5d f4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}