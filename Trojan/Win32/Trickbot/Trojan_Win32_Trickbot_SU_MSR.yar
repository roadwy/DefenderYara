
rule Trojan_Win32_Trickbot_SU_MSR{
	meta:
		description = "Trojan:Win32/Trickbot.SU!MSR,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 00 4e 00 49 00 4d 00 54 00 45 00 53 00 54 00 20 00 4d 00 46 00 43 00 20 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 } //1 ANIMTEST MFC Application
		$a_01_1 = {8b 17 2b d3 89 17 89 79 08 5f 5e 5d 5b 59 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}