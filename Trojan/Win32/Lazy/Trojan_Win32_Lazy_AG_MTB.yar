
rule Trojan_Win32_Lazy_AG_MTB{
	meta:
		description = "Trojan:Win32/Lazy.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 f0 6d 66 89 45 e0 0f bf 4d c4 33 4d ec 81 f1 e4 03 00 00 88 4d fa 6b 15 40 21 4c 00 00 83 f2 3a 89 15 58 21 4c 00 8b 45 d8 35 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}