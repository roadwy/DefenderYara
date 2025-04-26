
rule Trojan_Win32_SpySnake_MV_MTB{
	meta:
		description = "Trojan:Win32/SpySnake.MV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c0 83 c4 10 8b c8 85 f6 74 1b 8b c1 99 c7 45 c8 0c 00 00 00 f7 7d c8 8a 82 08 e5 40 00 30 04 0b 41 3b ce 72 e5 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}