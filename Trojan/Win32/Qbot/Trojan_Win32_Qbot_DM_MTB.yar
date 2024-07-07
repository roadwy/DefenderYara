
rule Trojan_Win32_Qbot_DM_MTB{
	meta:
		description = "Trojan:Win32/Qbot.DM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 6a 00 e8 90 02 04 03 d8 6a 00 e8 90 02 04 2b d8 6a 00 e8 90 02 04 03 d8 6a 00 e8 90 02 04 2b d8 8b 45 d4 31 18 83 45 ec 04 83 45 d4 04 8b 45 ec 3b 45 d0 72 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}