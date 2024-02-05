
rule Trojan_Win32_SpySnake_MW_MTB{
	meta:
		description = "Trojan:Win32/SpySnake.MW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {83 c4 10 33 c9 85 db 74 16 8b c1 99 6a 0c 5e f7 fe 8a 82 70 d6 40 00 30 04 0f 41 3b cb 72 ea } //00 00 
	condition:
		any of ($a_*)
 
}