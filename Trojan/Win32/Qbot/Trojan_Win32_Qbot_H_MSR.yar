
rule Trojan_Win32_Qbot_H_MSR{
	meta:
		description = "Trojan:Win32/Qbot.H!MSR,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 44 24 0c 8b 4c 24 14 8b 54 24 10 be 00 01 00 00 8b 7c 24 2c 81 f7 90 01 04 01 f9 89 44 24 08 89 c8 89 54 24 04 99 f7 fe 8b 4c 24 1c 8a 1c 11 0f b6 fb 8b 4c 24 08 01 f9 89 c8 89 14 24 99 f7 fe 8b 4c 24 1c 8a 3c 11 8b 34 24 88 3c 31 88 1c 11 8a 5c 24 1b 80 f3 b2 8a 3c 31 88 5c 24 3f 8b 4c 24 24 8b 74 24 04 8a 1c 31 0f b6 cf 01 f9 81 e1 ff 00 00 00 8b 7c 24 1c 32 1c 0f 8b 4c 24 20 88 1c 31 83 c6 01 69 4c 24 40 9e 47 97 49 89 4c 24 40 8b 4c 24 28 39 ce 8b 0c 24 89 4c 24 14 89 74 24 10 89 54 24 0c 0f 84 36 ff ff ff e9 4d ff ff ff 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}