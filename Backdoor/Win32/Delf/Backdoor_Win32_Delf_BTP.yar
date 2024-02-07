
rule Backdoor_Win32_Delf_BTP{
	meta:
		description = "Backdoor:Win32/Delf.BTP,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //01 00  SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {6f 6e 73 61 66 65 74 79 2e 6e 65 74 2f 78 70 64 65 6d 6f 6e 2e 70 68 70 3f 6e 6f 3d } //01 00  onsafety.net/xpdemon.php?no=
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 58 50 44 65 6d 6f 6e } //01 00  SOFTWARE\XPDemon
		$a_01_3 = {54 49 64 54 43 50 43 6c 69 65 6e 74 } //01 00  TIdTCPClient
		$a_01_4 = {54 50 6f 70 75 70 4c 69 73 74 } //01 00  TPopupList
		$a_01_5 = {67 65 74 68 6f 73 74 62 79 6e 61 6d 65 } //01 00  gethostbyname
		$a_01_6 = {73 65 6e 64 74 6f } //01 00  sendto
		$a_01_7 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //00 00  GetClipboardData
	condition:
		any of ($a_*)
 
}