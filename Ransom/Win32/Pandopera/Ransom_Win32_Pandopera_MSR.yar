
rule Ransom_Win32_Pandopera_MSR{
	meta:
		description = "Ransom:Win32/Pandopera!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 54 45 4d 50 5c 50 61 6e 64 61 5c 73 70 70 73 65 72 2e 65 78 65 } //1 C:\TEMP\Panda\sppser.exe
		$a_01_1 = {43 00 3a 00 5c 00 54 00 45 00 4d 00 50 00 5c 00 50 00 61 00 6e 00 64 00 61 00 5c 00 5c 00 2a 00 2e 00 73 00 66 00 74 00 } //1 C:\TEMP\Panda\\*.sft
		$a_01_2 = {77 00 69 00 6e 00 6d 00 73 00 69 00 73 00 6d 00 2e 00 65 00 78 00 65 00 } //1 winmsism.exe
		$a_01_3 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 68 00 6f 00 73 00 74 00 6f 00 70 00 65 00 72 00 61 00 74 00 69 00 6f 00 6e 00 73 00 79 00 73 00 74 00 65 00 6d 00 73 00 2e 00 63 00 6f 00 6d 00 } //1 https://hostoperationsystems.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}