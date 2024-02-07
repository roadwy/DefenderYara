
rule TrojanSpy_Win32_Platcyber_A{
	meta:
		description = "TrojanSpy:Win32/Platcyber.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {50 61 73 73 77 6f 72 64 45 64 69 74 4b 65 79 50 72 65 73 73 } //02 00  PasswordEditKeyPress
		$a_01_1 = {26 74 79 70 65 3d 73 65 63 72 65 74 26 64 61 74 61 3d } //01 00  &type=secret&data=
		$a_01_2 = {26 74 79 70 65 3d 70 75 62 6b 65 79 73 26 64 61 74 61 3d } //02 00  &type=pubkeys&data=
		$a_01_3 = {69 38 62 68 31 50 72 4a 69 66 72 4d 34 71 } //00 00  i8bh1PrJifrM4q
	condition:
		any of ($a_*)
 
}