
rule Trojan_Win64_SilkLoader_MA_MTB{
	meta:
		description = "Trojan:Win64/SilkLoader.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6b c8 34 41 8a c0 41 ff c0 2a c1 04 35 41 30 01 49 ff c1 41 83 f8 16 7c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}