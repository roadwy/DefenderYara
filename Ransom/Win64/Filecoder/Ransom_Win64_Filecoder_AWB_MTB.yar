
rule Ransom_Win64_Filecoder_AWB_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.AWB!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {45 6e 63 72 79 70 74 69 6e 67 20 66 69 6c 65 73 20 69 6e 20 64 69 72 65 63 74 6f 72 79 3a } //5 Encrypting files in directory:
		$a_01_1 = {43 3a 5c 48 45 4c 50 2d 52 41 4e 53 4f 4d 57 41 52 45 2e 74 78 74 } //1 C:\HELP-RANSOMWARE.txt
		$a_01_2 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 4e 6f 50 72 6f 66 69 6c 65 20 2d 46 69 6c 65 } //1 powershell -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -File
		$a_01_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}