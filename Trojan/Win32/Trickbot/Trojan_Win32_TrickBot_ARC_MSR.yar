
rule Trojan_Win32_TrickBot_ARC_MSR{
	meta:
		description = "Trojan:Win32/TrickBot.ARC!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6f 74 68 65 72 73 20 61 73 20 77 65 6c 6c 2e 65 78 65 } //1 others as well.exe
		$a_01_1 = {47 73 38 4c 48 73 7a 4a 48 73 } //1 Gs8LHszJHs
		$a_01_2 = {53 75 6e 67 61 69 20 50 65 74 61 6e 69 20 4d 61 6c 61 79 73 69 61 } //1 Sungai Petani Malaysia
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}