
rule Trojan_Win32_Trickbot_RTC_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.RTC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_02_0 = {33 c0 3b eb 7e ?? 8b 54 24 ?? 8d 4c 2a ?? 8a 11 88 ?? ?? ?? ?? ?? 40 49 3b c5 7c ?? 8d 45 ?? 83 f8 3e 88 9d ?? ?? ?? ?? 7d } //1
		$a_01_1 = {66 6f 72 74 69 20 61 6e 74 69 76 69 72 75 73 20 73 74 75 70 69 64 20 70 72 6f 74 65 63 74 69 6f 6e } //1 forti antivirus stupid protection
		$a_01_2 = {26 54 37 37 34 61 29 77 25 2a 4b 50 6a 39 53 } //5 &T774a)w%*KPj9S
		$a_01_3 = {6d 73 75 79 44 43 59 6a 46 26 49 51 34 45 59 } //5 msuyDCYjF&IQ4EY
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5) >=7
 
}