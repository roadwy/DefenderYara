
rule Trojan_Win32_Qakbot_CNG_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.CNG!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 44 85 d8 33 c2 eb 01 40 80 3c 08 00 75 f9 c9 c3 } //1
		$a_01_1 = {c7 45 dc 38 5b 5b 4d } //1
		$a_01_2 = {8a 44 0d dc 04 09 88 44 0d c0 41 83 f9 1b 7c f0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}