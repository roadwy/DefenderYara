
rule Ransom_Win32_Buran_A_MSR{
	meta:
		description = "Ransom:Win32/Buran.A!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {42 55 52 41 4e [0-20] 53 54 4f 52 4d } //1
		$a_01_1 = {55 6e 69 6e 73 74 61 6c 6c 2f 64 69 73 61 62 6c 65 20 61 6c 6c 20 61 6e 74 69 76 69 72 75 73 20 28 61 6e 64 20 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 29 20 62 65 66 6f 72 65 20 75 73 69 6e 67 20 74 68 69 73 } //1 Uninstall/disable all antivirus (and Windows Defender) before using this
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 42 75 72 61 6e 20 56 5c 53 74 6f 70 } //1 Software\Buran V\Stop
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}