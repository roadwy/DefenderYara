
rule Trojan_Win32_Pikabot_HO_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.HO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 04 68 00 30 00 00 56 6a 00 ff 55 } //1
		$a_01_1 = {8b c1 83 e0 07 8a 44 38 10 30 04 19 41 3b ce 72 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}