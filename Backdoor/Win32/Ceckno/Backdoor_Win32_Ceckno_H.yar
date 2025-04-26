
rule Backdoor_Win32_Ceckno_H{
	meta:
		description = "Backdoor:Win32/Ceckno.H,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 45 54 20 5e 26 26 25 24 25 24 5e 25 24 23 5e 26 2a 2a } //1 GET ^&&%$%$^%$#^&**
		$a_00_1 = {4d 61 64 65 20 69 6e 20 43 68 69 6e 61 20 44 44 6f 53 } //1 Made in China DDoS
		$a_00_2 = {4e 65 74 77 6f 72 6b 20 43 68 69 6e 61 20 4e 65 74 42 6f 74 } //1 Network China NetBot
		$a_00_3 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c } //1 SYSTEM\CurrentControlSet\Services\
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}