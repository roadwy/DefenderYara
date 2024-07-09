
rule Trojan_Win32_Dogrobot_gen_C{
	meta:
		description = "Trojan:Win32/Dogrobot.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 7d 0c 09 76 19 83 7d 0c 14 73 13 66 c7 45 ?? 31 00 0f b7 45 0c 83 c0 26 66 89 45 ?? eb 2a 83 7d 0c 13 76 19 83 7d 0c 1e 73 13 66 c7 45 ?? 32 00 0f b7 45 0c 83 c0 1c 66 89 45 ?? eb 0b 0f b7 45 0c 83 c0 30 66 89 45 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}