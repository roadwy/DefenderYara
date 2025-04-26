
rule Trojan_Win32_Trickbot_PI{
	meta:
		description = "Trojan:Win32/Trickbot.PI,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 0f be 0c 10 8b 55 ?? 03 55 ?? 0f b6 02 33 c1 8b 4d ?? 03 4d ?? 88 01 } //3
		$a_03_1 = {5c 54 69 6e 69 5c 64 64 73 61 6d 70 5c [0-10] 5c 64 64 73 61 6d 70 2e 70 64 62 } //1
		$a_03_2 = {5c 50 72 6f 6a 65 63 74 5f 30 31 5c [0-10] 5c 7a 47 63 72 76 6a 4a 6d 4f 58 78 66 2e 70 64 62 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=4
 
}