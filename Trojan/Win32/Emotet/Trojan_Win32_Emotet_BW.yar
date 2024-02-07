
rule Trojan_Win32_Emotet_BW{
	meta:
		description = "Trojan:Win32/Emotet.BW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {40 67 2d 65 33 65 5f 32 71 61 6c 41 4e 2b 2f 50 61 4b 56 2f 4a 2e 70 64 62 } //01 00  @g-e3e_2qalAN+/PaKV/J.pdb
		$a_01_1 = {44 00 65 00 62 00 75 00 67 00 67 00 65 00 72 00 } //01 00  Debugger
		$a_01_2 = {41 00 20 00 6f 00 64 00 20 00 42 00 52 00 57 00 51 00 45 00 57 00 4a 00 20 00 6a 00 71 00 20 00 4d 00 79 00 77 00 6d 00 79 00 20 00 59 00 62 00 20 00 51 00 } //00 00  A od BRWQEWJ jq Mywmy Yb Q
	condition:
		any of ($a_*)
 
}