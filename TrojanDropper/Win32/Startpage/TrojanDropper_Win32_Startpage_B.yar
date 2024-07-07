
rule TrojanDropper_Win32_Startpage_B{
	meta:
		description = "TrojanDropper:Win32/Startpage.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 ff 75 14 ff 75 10 8d 34 07 8a 04 07 50 e8 90 01 04 83 c4 0c 47 3b 7d 0c 88 06 7c e0 90 00 } //1
		$a_01_1 = {b8 66 06 00 00 39 45 10 be 88 08 00 00 75 17 50 ff 75 08 ff d7 6a 00 68 f4 01 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}