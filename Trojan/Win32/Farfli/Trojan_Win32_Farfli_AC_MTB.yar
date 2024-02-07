
rule Trojan_Win32_Farfli_AC_MTB{
	meta:
		description = "Trojan:Win32/Farfli.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 36 30 74 72 61 79 2e 65 78 65 } //01 00  360tray.exe
		$a_01_1 = {33 36 30 73 64 2e 65 78 65 } //01 00  360sd.exe
		$a_01_2 = {51 51 50 43 54 72 61 79 2e 65 78 65 } //01 00  QQPCTray.exe
		$a_01_3 = {45 4c 5f 48 69 64 65 4f 77 6e 65 72 } //00 00  EL_HideOwner
	condition:
		any of ($a_*)
 
}