
rule TrojanSpy_Win32_Bafi_I{
	meta:
		description = "TrojanSpy:Win32/Bafi.I,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c0 25 0f 00 00 80 79 05 48 83 c8 f0 40 (88 44 24 18 8a 04 31|88 45 ff 8b 45 08 8d 14 01 8a 02) 32 c3 } //10
		$a_00_1 = {8d 13 0b 37 79 1f ed cf 78 ae 63 30 70 8f ec 94 } //5
	condition:
		((#a_03_0  & 1)*10+(#a_00_1  & 1)*5) >=15
 
}