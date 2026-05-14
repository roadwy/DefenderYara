
rule Trojan_Win64_Vimditator_PGVD_MTB{
	meta:
		description = "Trojan:Win64/Vimditator.PGVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 85 ff 74 ab 40 30 2c 38 69 ed ?? ?? ?? ?? 81 c5 ?? ?? ?? ?? 48 ff c7 eb } //3
		$a_01_1 = {9e 91 71 34 61 ae 74 5e da 98 d3 8a 09 f0 11 36 e9 46 cb fb e9 14 46 e6 3a bb 39 d4 cc a9 22 e7 c4 e0 49 2f b4 0e 8b e8 52 30 4e 14 41 ed 95 6c bd f1 2c a7 ab } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}