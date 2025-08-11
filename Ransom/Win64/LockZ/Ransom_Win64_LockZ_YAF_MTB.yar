
rule Ransom_Win64_LockZ_YAF_MTB{
	meta:
		description = "Ransom:Win64/LockZ.YAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 20 79 6f 75 72 20 66 69 6c 65 73 20 62 61 63 6b } //1 get your files back
		$a_01_1 = {75 6e 6c 6f 63 6b 20 66 69 6c 65 73 20 79 6f 75 72 73 65 6c 66 } //1 unlock files yourself
		$a_01_2 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 } //1 powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass
		$a_01_3 = {69 6e 66 65 63 74 65 64 20 62 79 20 2a 2a 4c 6f 63 6b 5a 2a 2a } //1 infected by **LockZ**
		$a_01_4 = {64 65 6c 20 2f 71 20 2f 66 } //1 del /q /f
		$a_01_5 = {64 69 72 45 6e 63 72 79 70 74 69 6f 6e 2e 70 73 31 } //1 dirEncryption.ps1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}