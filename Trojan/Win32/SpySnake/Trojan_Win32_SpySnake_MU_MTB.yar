
rule Trojan_Win32_SpySnake_MU_MTB{
	meta:
		description = "Trojan:Win32/SpySnake.MU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {bf ab aa aa aa 0f 1f 80 00 00 00 00 89 c8 f7 e7 d1 ea 83 e2 fc 8d 04 52 89 ca 29 c2 0f b6 92 a2 da 41 00 30 14 0e f7 d8 0f b6 84 01 a3 da 41 00 30 44 0e 01 83 c1 02 39 cb 75 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}