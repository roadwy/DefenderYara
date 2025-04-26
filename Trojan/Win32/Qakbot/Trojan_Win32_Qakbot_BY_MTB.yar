
rule Trojan_Win32_Qakbot_BY_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.BY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 45 bc 8b 45 fc 8b 40 0c eb b1 8b 45 fc 0f b6 44 10 10 33 c8 3a f6 74 00 8b 45 ec 03 45 f0 88 08 e9 } //1
		$a_01_1 = {83 e8 01 8b 4d 14 83 d9 00 eb c5 40 89 45 f8 8b 45 10 66 3b db 74 e9 8a 09 88 08 8b 45 fc 66 3b c0 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}