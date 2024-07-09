
rule Trojan_Win32_DanaBot_AT_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 45 ?? 8b 45 ?? 03 45 ?? 89 45 ?? 8b 45 ?? 33 45 ?? 89 45 ?? 8b 45 ?? 33 45 ?? 89 45 ?? 83 25 } //1
		$a_02_1 = {8b 4d 60 8b 55 ?? 89 14 01 5b 83 c5 ?? 8b e5 5d } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}