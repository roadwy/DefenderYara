
rule Trojan_Win32_DanaBot_AT_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 45 90 01 01 8b 45 90 01 01 03 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 33 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 33 45 90 01 01 89 45 90 01 01 83 25 90 00 } //1
		$a_02_1 = {8b 4d 60 8b 55 90 01 01 89 14 01 5b 83 c5 90 01 01 8b e5 5d 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}