
rule Trojan_Win32_Danabot_A_MTB{
	meta:
		description = "Trojan:Win32/Danabot.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 89 e5 83 ec 14 52 57 56 31 c0 66 8c c9 80 f9 1b 0f 84 8f 00 00 00 8b 75 08 8b 7d 0c 8b 55 10 89 65 ec 83 e4 f0 6a 33 e8 00 00 00 00 83 04 24 05 cb } //2
		$a_81_1 = {63 61 72 64 5f 6e 75 6d 62 65 72 5f 65 6e 63 72 79 70 74 65 64 } //1 card_number_encrypted
		$a_81_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 49 6e 74 65 6c 6c 69 46 6f 72 6d 73 5c 53 74 6f 72 61 67 65 32 } //1 Software\Microsoft\Internet Explorer\IntelliForms\Storage2
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=4
 
}