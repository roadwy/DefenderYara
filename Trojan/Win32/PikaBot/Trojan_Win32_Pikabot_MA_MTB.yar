
rule Trojan_Win32_Pikabot_MA_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 41 40 8b cb 2b 05 90 01 04 05 a5 0c 09 00 c1 e9 08 31 05 90 01 04 a1 90 01 04 88 0c 10 8b 0d 90 01 04 a1 90 01 04 41 89 0d 90 01 04 88 1c 08 ff 05 90 01 04 81 fe 34 6a 01 00 0f 8c 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}