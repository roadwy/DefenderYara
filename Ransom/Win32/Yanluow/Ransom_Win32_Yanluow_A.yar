
rule Ransom_Win32_Yanluow_A{
	meta:
		description = "Ransom:Win32/Yanluow.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 03 00 "
		
	strings :
		$a_80_0 = {2e 79 61 6e 6c 75 6f 77 61 6e 67 } //.yanluowang  01 00 
		$a_80_1 = {6e 65 74 20 73 74 6f 70 20 57 69 6e 44 65 66 65 6e 64 } //net stop WinDefend  01 00 
		$a_80_2 = {6e 65 74 20 73 74 6f 70 20 53 68 61 64 6f 77 50 72 6f 74 65 63 74 53 76 63 } //net stop ShadowProtectSvc  01 00 
		$a_80_3 = {6e 65 74 20 73 74 6f 70 20 4d 53 45 78 63 68 61 6e 67 65 53 41 } //net stop MSExchangeSA  01 00 
		$a_80_4 = {6e 65 74 20 73 74 6f 70 20 51 42 43 46 4d 6f 6e 69 74 6f 72 53 65 72 76 69 63 65 } //net stop QBCFMonitorService  01 00 
		$a_80_5 = {6e 65 74 20 73 74 6f 70 20 51 75 69 63 6b 42 6f 6f 6b 73 } //net stop QuickBooks  01 00 
		$a_80_6 = {2f 63 20 70 6f 77 65 72 73 68 65 6c 6c 20 2d 63 6f 6d 6d 61 6e 64 20 22 47 65 74 2d 56 4d 20 7c 20 53 74 6f 70 2d 56 4d 20 2d 46 6f 72 63 65 } ///c powershell -command "Get-VM | Stop-VM -Force  00 00 
		$a_00_7 = {5d 04 00 00 } //4c bd 
	condition:
		any of ($a_*)
 
}