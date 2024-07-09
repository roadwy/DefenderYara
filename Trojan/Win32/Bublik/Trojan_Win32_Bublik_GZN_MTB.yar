
rule Trojan_Win32_Bublik_GZN_MTB{
	meta:
		description = "Trojan:Win32/Bublik.GZN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 f7 d1 0f b7 c5 66 ff c1 13 c1 66 33 d9 23 c2 25 ?? ?? ?? ?? 81 ef 02 00 00 00 66 89 0f f7 d0 } //10
		$a_01_1 = {66 65 5a 76 67 50 74 64 76 76 } //1 feZvgPtdvv
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}