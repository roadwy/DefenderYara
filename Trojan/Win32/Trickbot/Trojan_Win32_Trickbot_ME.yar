
rule Trojan_Win32_Trickbot_ME{
	meta:
		description = "Trojan:Win32/Trickbot.ME,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {6d 65 78 65 63 90 02 01 2e 64 6c 6c 00 43 6f 6e 74 72 6f 6c 90 00 } //1
		$a_03_1 = {57 61 6e 74 c7 90 01 02 52 65 6c 65 c7 90 01 02 61 73 65 00 90 00 } //1
		$a_03_2 = {6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 01 8d 90 02 10 ff 15 90 01 04 85 c0 74 23 6a 00 6a 02 68 00 00 00 a0 6a 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}