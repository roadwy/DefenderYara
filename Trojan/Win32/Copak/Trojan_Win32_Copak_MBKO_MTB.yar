
rule Trojan_Win32_Copak_MBKO_MTB{
	meta:
		description = "Trojan:Win32/Copak.MBKO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c6 01 8d 43 01 89 c3 3b 5d bc 76 05 bb 01 00 00 00 b8 ?? ?? ?? ?? 8d 7e 01 ba ?? ?? ?? ?? 8a 44 38 ff 8a 54 1a ff 30 c2 8b 7d c0 8d 04 37 88 10 39 f1 77 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}