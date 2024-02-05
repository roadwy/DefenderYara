
rule TrojanSpy_Win32_Casbaneiro_A{
	meta:
		description = "TrojanSpy:Win32/Casbaneiro.A,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 44 65 73 6b 43 6f 72 69 6e 67 61 5c 44 65 73 6b 74 6f 70 5c 74 6f 20 43 6f 72 69 6e 67 61 5c 6d 4f 52 4d 6f 74 2d 6d 61 73 74 65 72 5c } //0a 00 
		$a_01_1 = {45 3a 5c 54 6f 70 73 5c 43 6f 6d 70 6f 6e 65 6e 74 65 73 5c 6d 4f 52 4d 6f 74 2d 6d 61 73 74 65 72 5c } //00 00 
	condition:
		any of ($a_*)
 
}