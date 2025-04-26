
rule Trojan_Win32_SpySnake_MT_MTB{
	meta:
		description = "Trojan:Win32/SpySnake.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 ab aa aa aa f7 e1 c1 ea 03 8d 14 52 03 d2 03 d2 8b c1 2b c2 8a ?? ?? ?? ?? ?? 30 14 0b 41 3b ce 72 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}