
rule Trojan_Win64_PandoraBlade_B_dha{
	meta:
		description = "Trojan:Win64/PandoraBlade.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 4e 6f 50 72 6f 66 69 6c 65 20 2d 43 6f 6d 6d 61 6e 64 20 41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 } //powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -Command Add-MpPreference -ExclusionPath  1
		$a_80_1 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 4d 69 63 72 6f 73 6f 66 74 2e 4e 45 54 5c 46 72 61 6d 65 77 6f 72 6b 5c 76 34 2e 30 2e 33 30 33 31 39 5c 63 76 74 72 65 73 2e 65 78 65 } //C:\Windows\Microsoft.NET\Framework\v4.0.30319\cvtres.exe  1
		$a_80_2 = {50 61 6e 64 6f 72 61 20 68 56 4e 43 } //Pandora hVNC  1
		$a_80_3 = {50 61 6e 64 6f 72 61 20 57 49 4c 4c 20 4e 4f 54 20 62 65 20 69 6e 73 74 61 6c 6c 65 64 20 74 6f 20 79 6f 75 72 20 73 79 73 74 65 6d } //Pandora WILL NOT be installed to your system  1
		$a_80_4 = {44 65 6c 65 67 61 74 65 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //DelegateWriteProcessMemory  1
		$a_80_5 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 } //explorer.exe  1
		$a_80_6 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
		$a_80_7 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 } //CreateProcessA  1
		$a_80_8 = {52 75 6e 50 45 } //RunPE  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1) >=9
 
}