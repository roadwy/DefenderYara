
rule Trojan_Win32_Qbot_NEAC_MTB{
	meta:
		description = "Trojan:Win32/Qbot.NEAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 55 f4 03 55 c8 8b 45 ec 03 45 c4 8b 4d d4 e8 ?? ?? ?? ?? 8b 45 d4 01 45 c4 8b 45 d4 01 45 c8 8b 45 d0 01 45 c8 eb c6 } //5
		$a_01_1 = {03 d8 8b 45 ec 31 18 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}