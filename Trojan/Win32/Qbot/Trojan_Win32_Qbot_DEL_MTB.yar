
rule Trojan_Win32_Qbot_DEL_MTB{
	meta:
		description = "Trojan:Win32/Qbot.DEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 f9 88 cb 0f b6 cb 66 c7 44 24 36 00 00 8b 7c 24 28 8b 44 24 04 8a 1c 07 66 c7 44 24 36 00 00 8b 44 24 20 8a 3c 08 30 df 66 c7 44 24 36 ?? ?? 8b 4c 24 24 8b 44 24 04 88 3c 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}