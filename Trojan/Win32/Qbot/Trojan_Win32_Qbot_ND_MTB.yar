
rule Trojan_Win32_Qbot_ND_MTB{
	meta:
		description = "Trojan:Win32/Qbot.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 7c 24 18 81 90 02 05 01 90 02 05 81 90 02 07 8b 90 02 03 8b 17 90 18 0f 90 02 06 2b c8 83 90 02 02 81 90 02 05 89 90 02 05 89 17 83 90 02 02 89 90 02 05 8b 90 02 05 83 90 02 02 89 90 02 03 03 d0 ff 90 02 03 0f 85 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}