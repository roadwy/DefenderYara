
rule Trojan_Win32_Bulz_GZF_MTB{
	meta:
		description = "Trojan:Win32/Bulz.GZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 24 33 d2 89 54 24 0c 50 89 54 24 14 66 c7 44 24 10 02 00 89 54 24 18 89 54 24 1c e8 ?? ?? ?? ?? 8b 74 24 20 66 89 44 24 0e 85 f6 ?? ?? 56 e8 ?? ?? ?? ?? 89 44 24 10 ?? ?? 56 e8 } //10
		$a_01_1 = {7a 61 63 63 6c 2e 63 6f 6d } //1 zaccl.com
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}