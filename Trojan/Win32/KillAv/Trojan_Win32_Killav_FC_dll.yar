
rule Trojan_Win32_Killav_FC_dll{
	meta:
		description = "Trojan:Win32/Killav.FC!dll,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {49 66 2d 4e 6f 6e 65 2d 4d 61 74 63 68 3a 20 22 36 30 37 39 34 2d 31 32 62 33 2d 65 34 31 36 39 34 34 30 22 } //1 If-None-Match: "60794-12b3-e4169440"
		$a_01_1 = {25 73 25 64 00 00 00 00 25 73 20 2f 73 20 2c 25 73 00 00 00 25 73 5c 25 64 2e 6c 6e 6b } //1
		$a_01_2 = {25 00 73 00 5c 00 25 00 73 00 00 00 25 00 73 00 5c 00 2a 00 00 00 00 00 25 00 73 00 2a 00 2e 00 2a } //1
		$a_01_3 = {25 64 25 6e 00 00 00 00 25 32 35 35 5b 5e 2f 3a 5d } //1
		$a_01_4 = {14 5a 01 10 00 00 00 00 2e 48 00 00 5c 62 72 70 63 73 73 2e 64 6c 6c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}