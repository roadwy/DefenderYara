
rule TrojanSpy_Win32_Howjey_A{
	meta:
		description = "TrojanSpy:Win32/Howjey.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {57 69 6e 64 6f 77 73 20 4c 69 76 65 20 48 6f 6a 65 } //01 00  Windows Live Hoje
		$a_01_1 = {62 6f 75 6e 64 61 72 79 3d 22 3d 5f 4e 65 78 74 50 61 72 74 5f 32 72 66 6b } //01 00  boundary="=_NextPart_2rfk
		$a_01_2 = {73 6d 74 70 2e 62 72 61 2e 74 65 72 72 61 2e 63 6f 6d 2e 62 72 } //01 00  smtp.bra.terra.com.br
		$a_01_3 = {4d 53 4e 32 54 69 6d 65 72 } //01 00  MSN2Timer
		$a_01_4 = {3c 3c 4c 49 4e 4b 31 3e 3e } //00 00  <<LINK1>>
	condition:
		any of ($a_*)
 
}