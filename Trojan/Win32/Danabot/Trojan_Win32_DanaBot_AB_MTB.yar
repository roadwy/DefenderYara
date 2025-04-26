
rule Trojan_Win32_DanaBot_AB_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c7 33 cd c1 e8 ?? 03 44 24 ?? 89 44 24 ?? 89 4c 24 ?? 8b 44 24 ?? 31 44 24 ?? 2b 5c 24 ?? 8b 44 24 [0-40] ff 4c 24 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}