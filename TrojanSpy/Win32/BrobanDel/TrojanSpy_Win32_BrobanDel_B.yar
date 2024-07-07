
rule TrojanSpy_Win32_BrobanDel_B{
	meta:
		description = "TrojanSpy:Win32/BrobanDel.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {50 72 6f 6a 65 63 74 31 00 00 00 00 46 6f 72 6d 31 00 00 00 46 6f 72 6d 33 00 00 00 46 6f 72 6d 35 00 00 00 46 6f 72 6d 37 90 02 ff 46 6f 72 6d 35 33 90 02 ff 46 6f 72 6d 31 30 31 90 02 04 46 6f 72 6d 31 30 33 90 00 } //1
		$a_01_1 = {64 6d 46 79 49 46 38 77 65 47 } //1 dmFyIF8weG
		$a_01_2 = {58 48 67 33 4d 31 78 34 4e 7a 4e 63 65 44 5a 44 58 48 67 79 52 46 78 34 4e 7a 42 63 65 44 63 79 58 48 67 32 52 6c 78 34 4e 7a 68 63 65 44 63 35 } //1 XHg3M1x4NzNceDZDXHgyRFx4NzBceDcyXHg2Rlx4NzhceDc5
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}