
rule Trojan_Win32_Zbot_SIBL_MTB{
	meta:
		description = "Trojan:Win32/Zbot.SIBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 0c d6 8d 4c d6 04 0f c8 89 01 8b 45 90 01 01 8b 38 31 3c d6 8b 40 04 31 01 4a 89 55 90 01 01 0f 89 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}