
rule Trojan_Win32_SpyVoltar_KAA_MTB{
	meta:
		description = "Trojan:Win32/SpyVoltar.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {99 b9 e8 03 00 00 f7 f9 8b f2 81 c6 c8 } //2
		$a_01_1 = {99 b9 b0 04 00 00 f7 f9 83 c2 64 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}