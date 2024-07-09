
rule Trojan_Win32_Qbot_PBI_MTB{
	meta:
		description = "Trojan:Win32/Qbot.PBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 45 f0 0f b6 08 eb ?? 0f b6 44 10 ?? 33 c8 eb 3b bb 03 00 00 00 83 c3 05 eb ?? 8b 45 f0 33 d2 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}