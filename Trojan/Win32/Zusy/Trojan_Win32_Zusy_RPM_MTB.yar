
rule Trojan_Win32_Zusy_RPM_MTB{
	meta:
		description = "Trojan:Win32/Zusy.RPM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {4e 65 74 53 68 20 41 64 76 66 69 72 65 77 61 6c 6c 20 73 65 74 20 61 6c 6c 70 72 6f 66 69 6c 65 73 20 73 74 61 74 65 20 6f 66 66 } //1 NetSh Advfirewall set allprofiles state off
		$a_01_1 = {70 69 6e 67 20 31 39 32 2e 31 36 38 2e 33 2e 32 20 2d 6e 20 37 } //1 ping 192.168.3.2 -n 7
		$a_01_2 = {63 75 72 6c 20 2d 2d 75 72 6c } //1 curl --url
		$a_01_3 = {63 2e 74 65 6e 6f 72 2e 63 6f 6d } //1 c.tenor.com
		$a_01_4 = {74 72 6f 6c 6c 2d 74 72 6f 6c 6c 66 61 63 65 2e 67 69 66 20 2d 6f } //1 troll-trollface.gif -o
		$a_01_5 = {73 74 61 72 74 20 63 68 72 6f 6d 65 } //1 start chrome
		$a_01_6 = {31 30 2e 30 2e 32 2e 31 35 3a 33 30 30 30 2f 68 6f 6f 6b 2e 6a 73 } //1 10.0.2.15:3000/hook.js
		$a_01_7 = {53 6c 65 65 70 } //1 Sleep
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}