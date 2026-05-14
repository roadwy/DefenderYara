
rule Trojan_BAT_SelfDel_MK_MTB{
	meta:
		description = "Trojan:BAT/SelfDel.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 05 00 00 "
		
	strings :
		$a_01_0 = {70 72 61 67 6d 61 20 6e 61 6d 65 73 70 61 63 65 20 28 22 5c 5c 5c 5c 2e 5c 5c 72 6f 6f 74 5c 5c 43 49 4d 76 32 22 29 } //15 pragma namespace ("\\\\.\\root\\CIMv2")
		$a_01_1 = {6d 6f 66 63 6f 6d 70 20 24 6d 6f 66 50 61 74 68 } //10 mofcomp $mofPath
		$a_01_2 = {53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 63 6d 64 2e 65 78 65 20 2d 41 72 67 75 6d 65 6e 74 4c 69 73 74 20 22 2f 63 20 74 69 6d 65 6f 75 74 20 33 20 3e 20 6e 75 6c } //5 Start-Process cmd.exe -ArgumentList "/c timeout 3 > nul
		$a_01_3 = {53 65 6c 66 2d 64 65 6c 65 74 65 20 45 58 45 20 61 66 74 65 72 20 63 6f 6d 70 6c 65 74 69 6f 6e } //3 Self-delete EXE after completion
		$a_01_4 = {24 65 78 65 50 61 74 68 20 3d 20 5b 53 79 73 74 65 6d 2e 44 69 61 67 6e 6f 73 74 69 63 73 2e 50 72 6f 63 65 73 73 5d 3a 3a 47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 28 29 2e 4d 61 69 6e 4d 6f 64 75 6c 65 2e 46 69 6c 65 4e 61 6d 65 } //2 $exePath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5+(#a_01_3  & 1)*3+(#a_01_4  & 1)*2) >=35
 
}