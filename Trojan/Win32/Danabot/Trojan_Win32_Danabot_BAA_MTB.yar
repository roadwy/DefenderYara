
rule Trojan_Win32_Danabot_BAA_MTB{
	meta:
		description = "Trojan:Win32/Danabot.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 09 59 08 1f 16 5d 59 20 00 01 00 00 58 20 00 01 00 00 5d d1 13 04 07 11 04 6f ?? 00 00 0a 26 08 17 58 0c 08 06 8e 69 32 c0 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}