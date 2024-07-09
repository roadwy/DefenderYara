
rule Trojan_Win32_Qbot_PAU_MTB{
	meta:
		description = "Trojan:Win32/Qbot.PAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 f7 7d dc 8b 45 10 0f b6 14 10 03 ca 88 4d fe 0f b6 45 ?? 8b 4d 08 03 4d ?? 0f b6 11 33 d0 8b 45 08 03 45 f8 88 10 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}