
rule Trojan_Win64_BumbleBeeLoader_SFDB_MTB{
	meta:
		description = "Trojan:Win64/BumbleBeeLoader.SFDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_81_0 = {46 62 47 49 4e 36 37 38 } //2 FbGIN678
		$a_01_1 = {65 6e 6d 79 35 35 35 78 6f 37 39 2e 64 6c 6c } //1 enmy555xo79.dll
	condition:
		((#a_81_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}