
rule Trojan_Win32_Emotet_SC_MSR{
	meta:
		description = "Trojan:Win32/Emotet.SC!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 } //01 00  C:\ProgramData\
		$a_01_1 = {54 00 68 00 65 00 20 00 64 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 } //01 00  The document
		$a_01_2 = {50 00 6c 00 65 00 61 00 73 00 65 00 20 00 65 00 6e 00 74 00 65 00 72 00 20 00 61 00 20 00 63 00 75 00 72 00 72 00 65 00 6e 00 63 00 79 00 } //01 00  Please enter a currency
		$a_01_3 = {63 79 42 46 73 43 76 58 77 6d 2e 65 78 65 } //01 00  cyBFsCvXwm.exe
		$a_01_4 = {50 49 46 4d 47 52 2e 44 4c 4c } //00 00  PIFMGR.DLL
	condition:
		any of ($a_*)
 
}