
rule HackTool_Win32_AutoKMS_E_MSR{
	meta:
		description = "HackTool:Win32/AutoKMS.E!MSR,SIGNATURE_TYPE_PEHSTR,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4b 4d 53 20 4b 65 79 67 65 6e } //01 00  KMS Keygen
		$a_01_1 = {4b 4d 53 20 61 63 74 69 76 61 74 6f 72 73 } //01 00  KMS activators
		$a_01_2 = {4f 66 66 69 63 65 20 32 30 31 30 20 54 6f 6f 6c 6b 69 74 2e 70 64 62 } //01 00  Office 2010 Toolkit.pdb
		$a_01_3 = {4b 00 4d 00 53 00 45 00 6d 00 75 00 6c 00 61 00 74 00 6f 00 72 00 2e 00 65 00 78 00 65 00 } //01 00  KMSEmulator.exe
		$a_01_4 = {49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 41 00 75 00 74 00 6f 00 4b 00 4d 00 53 00 } //00 00  InstallAutoKMS
		$a_01_5 = {00 67 } //16 00  最
	condition:
		any of ($a_*)
 
}