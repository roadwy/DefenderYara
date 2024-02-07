
rule Trojan_Win32_ClipCoinGrab_A_MTB{
	meta:
		description = "Trojan:Win32/ClipCoinGrab.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {43 72 79 70 74 6f 20 43 75 72 72 65 6e 63 79 20 57 61 6c 6c 65 74 20 43 68 61 6e 67 65 72 5c 42 69 74 63 6f 69 6e 2d 47 72 61 62 62 65 72 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 42 69 74 63 6f 69 6e 2d 47 72 61 62 62 65 72 2e 70 64 62 } //01 00  Crypto Currency Wallet Changer\Bitcoin-Grabber\obj\Release\Bitcoin-Grabber.pdb
		$a_81_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_81_2 = {65 74 68 65 72 65 75 6d } //01 00  ethereum
		$a_81_3 = {42 69 74 63 6f 69 6e 2d 47 72 61 62 62 65 72 2e 65 78 65 } //01 00  Bitcoin-Grabber.exe
		$a_81_4 = {41 64 64 43 6c 69 70 62 6f 61 72 64 46 6f 72 6d 61 74 4c 69 73 74 65 6e 65 72 } //00 00  AddClipboardFormatListener
	condition:
		any of ($a_*)
 
}