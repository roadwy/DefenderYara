
rule TrojanDropper_Win32_Hesperbot_B{
	meta:
		description = "TrojanDropper:Win32/Hesperbot.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 64 72 6f 70 70 65 72 5f 78 38 36 2e 62 69 6e 00 5f 63 6f 72 65 5f 65 6e 74 72 79 40 34 } //01 00  搀潲灰牥硟㘸戮湩开潣敲敟瑮祲㑀
		$a_01_1 = {03 d8 8b 53 20 8b 4b 24 57 8b 7b 1c 03 d0 03 c8 03 f8 } //00 00 
		$a_00_2 = {87 } //10 00 
	condition:
		any of ($a_*)
 
}