
rule Trojan_Win32_DarkVNC_RPY_MTB{
	meta:
		description = "Trojan:Win32/DarkVNC.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c0 e0 04 2c 10 0a c3 32 c1 32 44 24 10 88 06 32 f8 83 c6 02 83 c5 02 eb 0d 8d 48 ff bf 01 00 00 00 c0 e1 04 0a cb 8a 02 84 c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}