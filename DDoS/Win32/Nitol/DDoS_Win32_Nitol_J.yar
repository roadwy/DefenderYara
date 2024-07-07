
rule DDoS_Win32_Nitol_J{
	meta:
		description = "DDoS:Win32/Nitol.J,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {25 64 2e 25 64 2e 25 64 2e 25 64 00 } //1
		$a_01_1 = {44 4e 53 46 6c 6f 6f 64 } //2 DNSFlood
		$a_01_2 = {31 39 32 2e 31 36 38 2e 31 2e 32 34 34 } //1 192.168.1.244
		$a_01_3 = {6a 64 66 77 6b 65 79 } //2 jdfwkey
		$a_01_4 = {83 c0 03 33 d2 0f af c6 f7 74 24 } //2
		$a_01_5 = {64 64 6f 73 2e 68 61 63 6b 78 6b 2e 63 6f 6d } //3 ddos.hackxk.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*3) >=8
 
}