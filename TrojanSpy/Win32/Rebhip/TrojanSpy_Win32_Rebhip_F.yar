
rule TrojanSpy_Win32_Rebhip_F{
	meta:
		description = "TrojanSpy:Win32/Rebhip.F,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {23 23 23 23 40 23 23 23 23 00 } //1 ⌣⌣⍀⌣#
		$a_01_1 = {5f 50 45 52 53 49 53 54 00 } //1
		$a_01_2 = {e3 fe f3 f3 e8 } //1
		$a_01_3 = {f4 f7 f9 e5 e3 ff f0 fd ef ef f9 ef e3 ee } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}