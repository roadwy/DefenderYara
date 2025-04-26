
rule Trojan_Win32_Abot_gen_A{
	meta:
		description = "Trojan:Win32/Abot.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 6c 64 69 62 6f 74 2d 62 79 2d 74 69 6c 6c 37 2e 63 68 } //1 aldibot-by-till7.ch
		$a_03_1 = {6f 70 48 54 54 50 44 44 6f 53 90 09 02 00 53 74 } //1
		$a_03_2 = {6f 70 54 43 50 44 44 6f 53 90 09 02 00 53 74 } //1
		$a_03_3 = {6f 70 44 44 6f 53 90 09 02 00 53 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}