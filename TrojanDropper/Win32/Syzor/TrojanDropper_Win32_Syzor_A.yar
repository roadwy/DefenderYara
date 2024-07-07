
rule TrojanDropper_Win32_Syzor_A{
	meta:
		description = "TrojanDropper:Win32/Syzor.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {37 2c 6d 73 95 65 83 d4 1c 08 12 cb 40 16 5b c4 d9 07 61 00 a7 a3 36 13 c0 c7 32 a6 77 6a 00 3b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}