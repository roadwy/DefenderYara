
rule Trojan_Win32_DanaBot_AH_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c1 2b f0 [0-25] 89 5c 24 ?? 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 [0-60] 31 44 24 [0-40] 03 54 24 ?? 89 54 24 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}