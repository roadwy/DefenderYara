
rule Trojan_Win32_Qsbot_A{
	meta:
		description = "Trojan:Win32/Qsbot.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {26 6d 61 69 6c 74 6f 5b 00 } //1
		$a_03_1 = {0f b7 10 66 89 14 06 83 c0 02 66 85 d2 75 f1 6a 00 8d 54 24 0c 52 6a 00 6a 00 68 ?? 0c 00 00 8d 41 04 8b 09 50 68 00 24 22 00 51 ff 15 ?? ?? ?? ?? 85 c0 0f 95 c0 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}