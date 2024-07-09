
rule Trojan_Win32_Qbot_MQ_MTB{
	meta:
		description = "Trojan:Win32/Qbot.MQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 55 fc 8a 09 88 0c 02 8b 55 ?? 83 c2 01 89 55 ?? eb } //1
		$a_02_1 = {33 c1 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? 8b ff 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 02 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}