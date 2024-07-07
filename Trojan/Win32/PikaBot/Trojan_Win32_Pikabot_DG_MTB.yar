
rule Trojan_Win32_Pikabot_DG_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e8 0f b6 4c 05 80 8b 45 e8 } //1
		$a_01_1 = {33 c8 8b 45 e8 88 4c 05 80 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}