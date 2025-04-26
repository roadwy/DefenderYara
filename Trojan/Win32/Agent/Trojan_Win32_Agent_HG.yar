
rule Trojan_Win32_Agent_HG{
	meta:
		description = "Trojan:Win32/Agent.HG,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 70 79 2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e } //3
		$a_01_1 = {47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 61 00 73 00 64 00 66 00 77 00 65 00 65 00 } //2 Global\asdfwee
		$a_01_2 = {72 62 2b 00 57 00 69 00 6e 00 53 00 74 00 61 00 30 } //1
		$a_01_3 = {73 76 63 68 6f 73 74 2e 64 6c 6c } //2 svchost.dll
		$a_01_4 = {2f 76 69 70 2f 31 33 31 32 2f 69 70 2e 74 78 74 } //2 /vip/1312/ip.txt
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=5
 
}