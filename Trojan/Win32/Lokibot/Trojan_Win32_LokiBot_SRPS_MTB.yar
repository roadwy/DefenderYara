
rule Trojan_Win32_LokiBot_SRPS_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.SRPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d f8 03 4d fc 0f be 11 81 f2 d7 00 00 00 8b 45 f8 03 45 fc 88 10 8b 4d f8 03 4d fc 8a 11 80 c2 01 8b 45 f8 03 45 fc 88 10 8b 4d f8 03 4d fc 8a 11 80 ea 01 8b 45 f8 03 45 fc 88 10 8b 4d f8 03 4d fc } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}