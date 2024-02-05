
rule Trojan_Win32_SpySnake_MQ_MTB{
	meta:
		description = "Trojan:Win32/SpySnake.MQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8a 04 37 34 76 04 7b 34 f2 2c 23 34 8e 04 42 34 d7 fe c0 88 04 37 46 3b f3 72 } //00 00 
	condition:
		any of ($a_*)
 
}