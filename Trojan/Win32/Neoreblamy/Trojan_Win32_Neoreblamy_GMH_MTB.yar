
rule Trojan_Win32_Neoreblamy_GMH_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.GMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b cf 8a 1c 01 8d 50 56 8a cb e8 ?? ?? ?? ?? 0f be f0 33 d2 0f be c3 03 45 fc 6a 19 59 f7 f1 8b 45 fc 8b ca d3 e6 8b 4d f8 03 ce 40 89 4d f8 89 45 fc 39 47 10 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Neoreblamy_GMH_MTB_2{
	meta:
		description = "Trojan:Win32/Neoreblamy.GMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 ec 40 89 45 ec 83 7d ec 03 ?? ?? 6a 01 8d 45 f8 50 6a 01 68 68 35 00 00 6a 00 68 32 2c 00 00 68 b9 38 00 00 e8 ?? ?? ?? ?? 83 c4 1c } //10
		$a_01_1 = {58 45 7a 4f 5a 44 55 54 58 66 74 45 55 42 48 6a 56 } //1 XEzOZDUTXftEUBHjV
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}