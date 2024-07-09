
rule Trojan_Win64_ZLoader_F{
	meta:
		description = "Trojan:Win64/ZLoader.F,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 6f 61 64 65 72 44 6c 6c 2e 64 6c 6c 00 [41-5a] 90 05 0c 03 61 2d 7a 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}