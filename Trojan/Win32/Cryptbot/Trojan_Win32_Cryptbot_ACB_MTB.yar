
rule Trojan_Win32_Cryptbot_ACB_MTB{
	meta:
		description = "Trojan:Win32/Cryptbot.ACB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 d0 89 95 f8 fe ff ff 8a 8c 15 fc fe ff ff 0f b6 c1 03 c3 0f b6 d8 8a 84 1d fc fe ff ff 88 84 15 fc fe ff ff 8b 85 f8 fe ff ff 0f b6 d1 88 8c 1d fc fe ff ff 0f b6 8c 05 fc fe ff ff 03 d1 0f b6 ca 0f b6 8c 0d fc fe ff ff 30 4e ff 83 ef 01 } //3
		$a_01_1 = {6f 00 53 00 61 00 62 00 6e 00 4e 00 } //2 oSabnN
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}