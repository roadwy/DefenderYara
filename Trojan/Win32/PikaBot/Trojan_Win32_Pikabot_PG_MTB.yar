
rule Trojan_Win32_Pikabot_PG_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.PG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 d1 8a 94 1d [0-04] 88 94 0d [0-04] 8b 55 ?? 88 84 1d [0-04] 02 84 0d [0-04] 0f b6 c0 8a 84 05 [0-04] 32 04 32 8b 55 ?? 88 04 32 46 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}