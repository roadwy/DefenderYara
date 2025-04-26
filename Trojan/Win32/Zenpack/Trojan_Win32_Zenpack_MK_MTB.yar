
rule Trojan_Win32_Zenpack_MK_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 8b 1a 83 c2 [0-01] 8b 01 42 42 33 c3 89 04 39 58 83 c1 [0-01] 3b 55 08 72 02 8b d6 3b c8 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}