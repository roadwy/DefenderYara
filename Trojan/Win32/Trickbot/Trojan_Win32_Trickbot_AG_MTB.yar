
rule Trojan_Win32_Trickbot_AG_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b c1 99 be 90 01 04 f7 fe 8a 99 90 01 04 8a 92 90 01 04 32 da 88 99 90 01 04 41 81 f9 90 01 04 75 90 00 } //1
		$a_02_1 = {56 57 51 8b 74 24 90 01 01 8b 7c 24 90 01 01 8b 4c 24 90 01 01 f3 a4 59 5f 5e c2 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}