
rule Trojan_Win64_ThunderStl_C{
	meta:
		description = "Trojan:Win64/ThunderStl.C,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 74 61 6e 64 61 6c 6f 6e 65 20 76 61 6c 75 65 73 20 6e 6f 74 20 61 6c 6c 6f 77 65 64 2e 20 57 61 73 20 67 69 76 65 6e 3a 20 7b 7d } //1 Standalone values not allowed. Was given: {}
		$a_01_1 = {43 6f 6e 66 69 67 20 66 69 6c 65 20 63 6f 6e 74 65 6e 74 73 3a } //1 Config file contents:
		$a_01_2 = {44 51 41 41 44 51 41 41 44 51 41 41 44 51 41 41 } //1 DQAADQAADQAADQAA
		$a_01_3 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 63 68 6f 63 6f 6c 61 74 65 79 5c 6c 69 62 5c 43 6f 6e 6e 68 6f 73 74 5c 74 6f 6f 6c 73 5c 73 62 2e 63 6f 6e 66 } //1 C:\ProgramData\chocolatey\lib\Connhost\tools\sb.conf
		$a_01_4 = {47 65 74 43 6f 6d 70 75 74 65 72 4e 61 6d 65 41 } //1 GetComputerNameA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}