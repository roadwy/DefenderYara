
rule Trojan_Win32_Dogrobot_gen_L{
	meta:
		description = "Trojan:Win32/Dogrobot.gen!L,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 43 01 89 45 e8 8b 45 e8 66 81 38 4d 5a 0f 85 ?? ?? ?? ?? 8b 45 e8 8b 70 3c 03 75 e8 8b 46 50 89 43 05 8b 45 e8 03 43 2f 8b 00 89 43 16 8b 45 e8 03 43 33 8b 00 89 43 1a 8b 45 e8 03 43 37 8b 00 89 43 1e 8d 43 26 50 ff 53 16 } //1
		$a_01_1 = {6a 40 68 00 30 00 00 8b 43 0d 50 6a 00 ff 53 4f 89 45 cc 83 7d cc 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}