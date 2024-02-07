
rule PWS_Win32_MSNer_A{
	meta:
		description = "PWS:Win32/MSNer.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 00 4c 00 69 00 76 00 65 00 4d 00 65 00 73 00 73 00 65 00 6e 00 67 00 65 00 72 00 } //01 00  TLiveMessenger
		$a_01_1 = {6e 6f 74 65 70 61 64 5c 73 65 63 72 65 74 2e 64 61 74 74 } //01 00  notepad\secret.datt
		$a_01_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 6d 73 6e 6d 73 67 72 2e 65 78 65 20 2f 66 } //01 00  taskkill /im msnmsgr.exe /f
		$a_00_3 = {77 00 61 00 67 00 6e 00 65 00 72 00 6d 00 69 00 32 00 32 00 2e 00 63 00 6f 00 6d 00 2f 00 65 00 6e 00 76 00 69 00 61 00 64 00 6f 00 72 00 2e 00 70 00 68 00 70 00 } //01 00  wagnermi22.com/enviador.php
		$a_01_4 = {33 72 64 70 61 72 74 79 5c 53 63 72 65 61 6d 53 65 63 5c 53 65 63 55 74 69 6c 73 2e 70 61 73 } //01 00  3rdparty\ScreamSec\SecUtils.pas
		$a_01_5 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 4e 54 69 63 65 5c } //00 00  SYSTEM\CurrentControlSet\Services\NTice\
	condition:
		any of ($a_*)
 
}