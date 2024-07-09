
rule Trojan_Win32_CobaltStrike_AG_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 cd cc cc cc 41 8b c9 41 f7 e1 41 ff c1 c1 ea ?? 8d 04 92 2b c8 48 63 c1 42 0f b6 0c 10 41 32 0c 38 48 8b 44 24 ?? 41 88 0c 00 49 ff c0 4c 3b c3 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}