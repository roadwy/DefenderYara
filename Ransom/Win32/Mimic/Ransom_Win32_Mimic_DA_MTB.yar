
rule Ransom_Win32_Mimic_DA_MTB{
	meta:
		description = "Ransom:Win32/Mimic.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 00 69 00 6d 00 69 00 63 00 20 00 34 00 2e 00 33 00 } //1 Mimic 4.3
		$a_01_1 = {44 00 65 00 6c 00 65 00 74 00 65 00 20 00 53 00 68 00 61 00 64 00 6f 00 77 00 20 00 43 00 6f 00 70 00 69 00 65 00 73 00 } //1 Delete Shadow Copies
		$a_01_2 = {5c 00 74 00 65 00 6d 00 70 00 5c 00 6c 00 6f 00 63 00 6b 00 2e 00 74 00 78 00 74 00 } //1 \temp\lock.txt
		$a_01_3 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 20 00 2d 00 45 00 78 00 65 00 63 00 75 00 74 00 69 00 6f 00 6e 00 50 00 6f 00 6c 00 69 00 63 00 79 00 20 00 42 00 79 00 70 00 61 00 73 00 73 00 20 00 22 00 47 00 65 00 74 00 2d 00 56 00 4d 00 20 00 7c 00 20 00 53 00 74 00 6f 00 70 00 2d 00 56 00 4d 00 } //1 powershell.exe -ExecutionPolicy Bypass "Get-VM | Stop-VM
		$a_01_4 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 43 00 6c 00 61 00 73 00 73 00 65 00 73 00 5c 00 6d 00 69 00 6d 00 69 00 63 00 66 00 69 00 6c 00 65 00 5c 00 73 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 } //1 Software\Classes\mimicfile\shell\open\command
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}