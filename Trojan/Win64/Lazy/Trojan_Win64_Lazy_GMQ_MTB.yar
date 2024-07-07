
rule Trojan_Win64_Lazy_GMQ_MTB{
	meta:
		description = "Trojan:Win64/Lazy.GMQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b f8 48 89 5d 20 48 89 75 28 48 b8 a9 8e ed 20 d1 e2 39 fe 48 89 45 10 48 89 75 18 66 0f 6f 45 10 66 0f ef 45 20 66 0f 7f 45 10 45 33 f6 4c 89 75 b0 48 c7 45 b8 0f 00 00 00 44 88 75 a0 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}