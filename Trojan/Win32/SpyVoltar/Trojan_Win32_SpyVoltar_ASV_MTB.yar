
rule Trojan_Win32_SpyVoltar_ASV_MTB{
	meta:
		description = "Trojan:Win32/SpyVoltar.ASV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 71 ff 8a 11 66 33 54 45 84 66 c1 c2 08 66 89 14 47 40 3b c6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}