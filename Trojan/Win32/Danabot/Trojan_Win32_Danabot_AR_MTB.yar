
rule Trojan_Win32_Danabot_AR_MTB{
	meta:
		description = "Trojan:Win32/Danabot.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 f0 03 4d ?? 8d 04 3b 33 c8 0f 57 c0 81 3d [0-30] 66 0f 13 05 ?? ?? ?? ?? 89 4d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}