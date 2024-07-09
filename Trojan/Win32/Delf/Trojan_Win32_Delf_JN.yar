
rule Trojan_Win32_Delf_JN{
	meta:
		description = "Trojan:Win32/Delf.JN,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_00_1 = {5c 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 73 79 73 61 66 65 74 79 } //1 \SYSTEM\CurrentControlSet\Services\sysafety
		$a_00_2 = {5c 53 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //1 \System32\drivers\etc\hosts
		$a_00_3 = {31 37 38 2e 36 33 2e 32 30 33 2e 31 33 33 } //1 178.63.203.133
		$a_02_4 = {77 77 77 2e 76 6b [0-08] 2e 72 75 } //1
		$a_00_5 = {43 6f 6e 74 72 6f 6c 6c 65 72 20 6f 66 20 63 6f 6d 70 75 74 65 72 20 73 61 66 65 74 79 } //1 Controller of computer safety
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}