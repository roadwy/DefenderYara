
rule Trojan_Win32_CobaltStrike_AST_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.AST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e1 c1 ea 04 8b ca c1 e1 04 03 ca 8b c6 8d 7f 06 2b c1 8b 4d ?? 03 c3 83 c3 06 0f b6 44 05 ?? 32 44 39 fa 88 47 ff 81 fb 00 10 05 00 0f 82 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}