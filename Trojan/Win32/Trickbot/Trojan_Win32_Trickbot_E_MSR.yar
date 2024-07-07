
rule Trojan_Win32_Trickbot_E_MSR{
	meta:
		description = "Trojan:Win32/Trickbot.E!MSR,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8d 45 d8 50 68 00 00 08 00 56 53 ff 15 90 e1 40 00 8b f8 85 ff 74 3e 8b 4d d8 85 c9 74 2f 33 c0 85 c9 74 0c } //1
		$a_01_1 = {80 34 30 74 40 8b 4d d8 3b c1 72 f4 } //1
		$a_01_2 = {6a 00 8d 45 cc c7 45 cc 00 00 00 00 50 51 56 ff 75 c8 ff 15 1c e0 40 00 8b 4d d8 8b f8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}