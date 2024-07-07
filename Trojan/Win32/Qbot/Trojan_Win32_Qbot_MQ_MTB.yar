
rule Trojan_Win32_Qbot_MQ_MTB{
	meta:
		description = "Trojan:Win32/Qbot.MQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 55 fc 8a 09 88 0c 02 8b 55 90 01 01 83 c2 01 89 55 90 01 01 eb 90 00 } //1
		$a_02_1 = {33 c1 8b ff c7 05 90 01 04 00 00 00 00 01 05 90 01 04 8b ff 8b 15 90 01 04 a1 90 01 04 89 02 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}