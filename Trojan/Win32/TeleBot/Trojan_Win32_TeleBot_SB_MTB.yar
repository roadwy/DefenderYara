
rule Trojan_Win32_TeleBot_SB_MTB{
	meta:
		description = "Trojan:Win32/TeleBot.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 14 38 8b 44 24 ?? 30 14 06 8b 6c 24 ?? 8b 5c 24 ?? 83 c6 ?? eb } //1
		$a_03_1 = {8b cd 2b cb b8 ?? ?? ?? ?? f7 e9 03 d1 c1 fa ?? 8b c2 c1 e8 ?? 03 c2 3b f0 73 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}