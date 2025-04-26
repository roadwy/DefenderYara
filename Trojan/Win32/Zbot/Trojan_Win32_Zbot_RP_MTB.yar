
rule Trojan_Win32_Zbot_RP_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {35 ac 00 74 64 8d 0c 10 0f af ca 31 c1 01 d1 80 c1 f8 88 0d ?? ?? ?? ?? 5d } //1
		$a_02_1 = {30 1c 06 89 d8 c1 eb 18 89 df c1 e0 08 89 45 ?? f7 d0 f7 d7 89 45 ?? 68 4f 00 6b 9b 50 e8 ?? ?? ?? ?? 83 c4 08 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}