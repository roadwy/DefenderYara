
rule Trojan_Win32_Pikabot_DJ_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.DJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 35 ?? 32 44 19 ?? 88 43 ?? 8d 04 1f 3d 00 f6 02 00 0f 82 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}