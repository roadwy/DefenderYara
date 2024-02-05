
rule TrojanSpy_Win32_Ploscato_B{
	meta:
		description = "TrojanSpy:Win32/Ploscato.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8d bd 40 ff ff ff b9 30 00 00 00 b8 cc cc cc cc f3 ab 83 7d 08 02 75 0c } //01 00 
		$a_01_1 = {5c 52 65 73 63 61 74 6f 72 5c } //00 00 
	condition:
		any of ($a_*)
 
}