
rule Trojan_Win32_Emotet_DBI_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {f7 f7 8b fa 8a 54 3c ?? 88 54 34 ?? 88 4c 3c ?? 0f b6 44 34 ?? 0f b6 c9 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8a 03 8a 54 14 ?? 32 c2 88 03 } //1
		$a_02_1 = {f7 f7 33 c0 8b fa 8a 54 3c ?? 88 54 34 ?? 8b 54 24 ?? 88 5c 3c ?? 8a 44 34 ?? 81 e2 ?? ?? ?? ?? bb ?? ?? ?? ?? 03 c2 99 f7 fb 8a 19 8a 44 14 ?? 32 d8 88 19 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}