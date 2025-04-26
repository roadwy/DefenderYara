
rule Trojan_Win32_DanaBot_AV_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.AV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 45 ?? 8b 45 ?? 03 45 ?? 89 45 ?? 8b 45 ?? 33 45 ?? 89 45 ?? 8b 45 ?? 33 45 } //1
		$a_02_1 = {8b 4d e0 8b 55 ?? 89 14 01 [0-10] 8b e5 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}