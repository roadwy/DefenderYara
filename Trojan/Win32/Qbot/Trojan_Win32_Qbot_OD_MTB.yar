
rule Trojan_Win32_Qbot_OD_MTB{
	meta:
		description = "Trojan:Win32/Qbot.OD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 4d e0 8a 55 f9 32 55 f9 88 55 f9 8a 10 8b 45 e4 89 c1 83 c1 01 66 8b 75 fa 66 90 01 04 66 89 75 fa 89 4d e4 88 10 eb 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}