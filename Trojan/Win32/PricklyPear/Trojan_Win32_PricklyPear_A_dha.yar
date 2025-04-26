
rule Trojan_Win32_PricklyPear_A_dha{
	meta:
		description = "Trojan:Win32/PricklyPear.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {30 1a 8a 02 3c 4d 74 0b 32 c3 88 02 80 c3 01 75 ef eb 06 8a c3 34 4d 88 02 33 f6 39 75 0c 76 12 8a 0c 16 8a c1 32 c3 8a d9 88 04 16 46 3b 75 0c 72 ee } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}