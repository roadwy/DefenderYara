
rule Trojan_Win64_Farfli_LMA_MTB{
	meta:
		description = "Trojan:Win64/Farfli.LMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 8b 43 10 49 ff c1 b8 7d e9 78 d5 f7 e9 03 d1 c1 fa 0b 8b c2 c1 e8 1f 03 d0 b8 cd cc cc cc 69 d2 98 09 00 00 2b ca 41 f7 e2 80 e9 02 43 30 0c 03 c1 ea 03 8d 0c 92 } //30
	condition:
		((#a_01_0  & 1)*30) >=30
 
}