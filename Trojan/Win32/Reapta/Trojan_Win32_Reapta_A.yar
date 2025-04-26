
rule Trojan_Win32_Reapta_A{
	meta:
		description = "Trojan:Win32/Reapta.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 2a 6e 61 6d 65 3d 22 63 61 70 74 63 68 61 22 } //1 .*name="captcha"
		$a_01_1 = {76 61 6c 75 65 3d 22 28 5b 5e 22 5d 2a 29 22 2e 2a } //1 value="([^"]*)".*
		$a_01_2 = {26 67 5f 73 69 64 3d 00 63 61 70 74 63 68 61 3d } //1 朦獟摩=慣瑰档㵡
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}