
rule Backdoor_Win32_Kriskynote_B{
	meta:
		description = "Backdoor:Win32/Kriskynote.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {b1 99 75 10 33 c0 85 db 7e 0a 30 0c 10 fe c1 40 3b c3 7c f6 5f 5e b8 01 00 00 00 5b c3 } //1
		$a_01_1 = {3b c5 76 1e 8a 04 3e 34 36 8a c8 80 e1 0f c0 e1 04 c0 e8 04 02 c8 88 0c 3e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}