
rule Trojan_Win32_PikaBot_CCIA_MTB{
	meta:
		description = "Trojan:Win32/PikaBot.CCIA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {03 45 e4 0f b6 08 eb } //01 00 
		$a_01_1 = {f7 f6 8b 45 f8 eb } //01 00 
		$a_01_2 = {0f b6 44 10 10 33 c8 eb } //01 00 
		$a_01_3 = {8b 45 dc 03 45 e4 e9 } //01 00 
		$a_01_4 = {8b 45 e4 40 e9 } //00 00 
	condition:
		any of ($a_*)
 
}