
rule Trojan_Win64_Lazy_NM_MTB{
	meta:
		description = "Trojan:Win64/Lazy.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {58 48 89 c3 48 ff c0 48 2d 00 10 3e 00 48 2d 24 2f 0c 10 48 05 1b 2f 0c 10 } //1
		$a_03_1 = {80 3b cc 75 ?? c6 03 00 bb 00 10 00 00 68 d0 18 0e 31 68 18 e3 2b 4f 53 50 e8 ?? ?? ?? ?? 48 83 c0 14 48 89 44 24 10 5b } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}