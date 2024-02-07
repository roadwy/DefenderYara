
rule Trojan_Win32_KillMBR_MB_MTB{
	meta:
		description = "Trojan:Win32/KillMBR.MB!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //01 00  \PhysicalDrive0
		$a_01_1 = {73 63 68 74 61 73 6b 73 2e 65 78 65 20 2f 43 72 65 61 74 65 20 2f 54 4e } //01 00  schtasks.exe /Create /TN
		$a_01_2 = {5c 45 46 49 5c 4d 69 63 72 6f 73 6f 66 74 5c 42 6f 6f 74 5c 62 6f 6f 74 6d 67 72 2e 65 66 69 } //01 00  \EFI\Microsoft\Boot\bootmgr.efi
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //00 00  Software\Microsoft\Windows\CurrentVersion\Run
	condition:
		any of ($a_*)
 
}