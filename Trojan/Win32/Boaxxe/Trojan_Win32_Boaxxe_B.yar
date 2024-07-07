
rule Trojan_Win32_Boaxxe_B{
	meta:
		description = "Trojan:Win32/Boaxxe.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b d8 8b 07 e8 90 01 03 ff 8b e8 85 ed 7e 2d be 01 00 00 00 83 c3 11 6b c3 71 25 ff 00 00 00 8b d8 88 1c 24 8b c7 e8 90 01 03 ff 8b 17 8a 54 32 ff 32 14 24 88 54 30 ff 46 4d 75 d8 90 00 } //1
		$a_02_1 = {ba 0b 00 00 00 e8 90 01 04 8d 55 d8 8b 45 90 01 01 e8 90 01 04 ff 75 d8 68 90 01 04 ff 75 90 01 01 8d 45 90 01 01 ba 03 00 00 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}