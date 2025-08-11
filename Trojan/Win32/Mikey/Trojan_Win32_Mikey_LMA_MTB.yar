
rule Trojan_Win32_Mikey_LMA_MTB{
	meta:
		description = "Trojan:Win32/Mikey.LMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f be 04 19 41 99 c7 45 fc d9 06 00 00 f7 7d fc 8b c6 c7 45 fc 05 00 00 00 80 c2 4f 30 14 37 33 d2 f7 75 fc f7 da 1b d2 23 ca 46 3b 75 0c } //15
		$a_03_1 = {8b 45 14 8b ce 8b 55 18 83 e1 07 c1 e1 03 e8 ?? ?? ?? ?? 30 04 1e 83 c6 01 83 d7 00 3b 7d 10 72 ?? ?? ?? 3b 75 0c 72 ?? 5f 5e 5b c9 c3 } //10
	condition:
		((#a_01_0  & 1)*15+(#a_03_1  & 1)*10) >=25
 
}