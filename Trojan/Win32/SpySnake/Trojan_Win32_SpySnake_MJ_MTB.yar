
rule Trojan_Win32_SpySnake_MJ_MTB{
	meta:
		description = "Trojan:Win32/SpySnake.MJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f4 03 45 f8 8a 08 88 4d ff 0f b6 55 ff 83 ea 7b 88 55 ff 0f b6 45 ff 35 a4 00 00 00 88 45 ff 0f b6 4d ff } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}