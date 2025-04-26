
rule Trojan_Win32_Dogrobot_gen_D{
	meta:
		description = "Trojan:Win32/Dogrobot.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 4d 44 20 4f 6e 65 0a } //1
		$a_01_1 = {43 72 61 63 6b 4d 65 2e 73 79 73 00 } //1
		$a_01_2 = {64 77 4e 65 65 64 65 64 53 69 7a 65 20 32 3a 20 25 64 } //1 dwNeededSize 2: %d
		$a_01_3 = {74 30 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}