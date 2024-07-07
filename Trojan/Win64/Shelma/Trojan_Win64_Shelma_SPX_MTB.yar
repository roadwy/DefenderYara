
rule Trojan_Win64_Shelma_SPX_MTB{
	meta:
		description = "Trojan:Win64/Shelma.SPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 0f b7 04 48 48 ff c1 48 33 c2 48 6b c0 1f 48 03 d0 49 3b c9 7c e9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}