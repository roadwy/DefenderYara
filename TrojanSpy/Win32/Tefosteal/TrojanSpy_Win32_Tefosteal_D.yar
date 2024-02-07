
rule TrojanSpy_Win32_Tefosteal_D{
	meta:
		description = "TrojanSpy:Win32/Tefosteal.D,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 00 69 00 6c 00 65 00 73 00 5c 00 49 00 6e 00 66 00 6f 00 50 00 43 00 2e 00 74 00 78 00 74 00 } //05 00  Files\InfoPC.txt
		$a_01_1 = {5c 00 69 00 6e 00 66 00 6f 00 70 00 63 00 2e 00 76 00 62 00 73 00 } //05 00  \infopc.vbs
		$a_01_2 = {5c 00 69 00 6e 00 66 00 6f 00 72 00 6d 00 2e 00 76 00 62 00 73 00 } //05 00  \inform.vbs
		$a_01_3 = {5c 00 66 00 69 00 6e 00 64 00 69 00 70 00 2e 00 76 00 62 00 73 00 } //05 00  \findip.vbs
		$a_01_4 = {5c 00 61 00 73 00 65 00 61 00 72 00 63 00 68 00 2e 00 76 00 62 00 73 00 } //01 00  \asearch.vbs
		$a_01_5 = {5c 00 46 00 69 00 6c 00 65 00 73 00 5c 00 44 00 69 00 73 00 63 00 6f 00 72 00 64 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 20 00 53 00 74 00 6f 00 72 00 61 00 67 00 65 00 } //01 00  \Files\Discord\Local Storage
		$a_01_6 = {50 61 73 73 77 6f 72 64 52 65 63 6f 76 65 72 79 43 68 72 6f 6d 65 2e 65 78 65 } //00 00  PasswordRecoveryChrome.exe
	condition:
		any of ($a_*)
 
}