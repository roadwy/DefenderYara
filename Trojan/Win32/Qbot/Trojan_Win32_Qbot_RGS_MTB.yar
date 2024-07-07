
rule Trojan_Win32_Qbot_RGS_MTB{
	meta:
		description = "Trojan:Win32/Qbot.RGS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 09 88 0c 02 8b 55 90 01 01 83 c2 01 89 55 90 01 01 eb c9 90 00 } //1
		$a_02_1 = {83 e8 15 a3 1c f1 60 00 8b 0d 90 01 04 03 4d 90 01 01 03 0d 90 01 04 89 0d 90 01 04 8b 15 90 01 04 2b 15 90 01 04 89 15 90 01 04 b8 01 00 00 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}