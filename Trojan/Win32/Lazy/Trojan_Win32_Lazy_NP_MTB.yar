
rule Trojan_Win32_Lazy_NP_MTB{
	meta:
		description = "Trojan:Win32/Lazy.NP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {4a 0c 39 4d 0c 72 0a 8b 42 08 03 c1 39 45 0c 72 0c 83 c2 28 3b d6 75 e7 33 c0 5e 5d c3 8b c2 eb f9 56 e8 1d 0a 00 00 85 c0 74 20 64 a1 18 00 00 00 be 58 81 46 00 8b 50 04 eb 04 3b d0 74 10 33 c0 8b ca f0 0f b1 0e 85 } //2
		$a_01_1 = {68 3c 23 45 00 68 bc 22 45 00 e8 72 9d 00 00 59 59 c7 05 54 81 46 00 02 00 00 00 eb 05 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}