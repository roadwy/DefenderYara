
rule TrojanSpy_Win32_Ardamax_W{
	meta:
		description = "TrojanSpy:Win32/Ardamax.W,SIGNATURE_TYPE_PEHSTR_EXT,33 00 33 00 03 00 00 "
		
	strings :
		$a_03_0 = {41 4b 4c 2e 30 30 ?? 00 } //50
		$a_00_1 = {d1 e8 40 8d 71 14 3b c2 72 05 b8 04 01 00 00 } //1
		$a_00_2 = {83 f8 12 74 18 83 f8 5b 74 13 83 f8 10 74 0e 83 f8 11 74 09 83 f8 5c 74 04 } //1
	condition:
		((#a_03_0  & 1)*50+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=51
 
}