
rule Trojan_Win32_Lokibot_CQ_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.CQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 4d fc 83 c1 01 89 4d fc 81 7d fc ?? ?? 00 00 73 ?? 8b 45 fc 33 d2 b9 04 00 00 00 f7 f1 8b [0-06] 0f be 0c 10 8b 55 fc 0f b6 ?? ?? ?? ?? ?? ?? 33 c1 8b 4d fc 88 [0-06] eb } //1
		$a_02_1 = {52 6a 40 68 ?? ?? 00 00 [0-08] ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a ?? 6a ?? 6a ?? 68 ?? ?? ?? ?? [0-06] ff } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}