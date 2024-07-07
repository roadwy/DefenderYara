
rule Trojan_Win32_Alureon_FI{
	meta:
		description = "Trojan:Win32/Alureon.FI,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {25 5b 5e 2e 5d 2e 25 5b 5e 28 5d 28 25 5b 5e 29 5d 29 } //1 %[^.].%[^(](%[^)])
		$a_01_1 = {70 68 7c 25 73 7c 25 73 7c 25 73 7c 25 73 } //1 ph|%s|%s|%s|%s
		$a_01_2 = {39 5e 1c 75 0d ff 76 10 ff 75 08 } //1
		$a_01_3 = {31 36 30 31 00 00 00 00 31 34 30 30 00 00 00 00 31 32 30 36 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}