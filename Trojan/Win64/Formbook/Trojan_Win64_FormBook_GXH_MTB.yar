
rule Trojan_Win64_FormBook_GXH_MTB{
	meta:
		description = "Trojan:Win64/FormBook.GXH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 0f f8 c3 66 0f f8 05 ?? ?? ?? ?? 66 0f d6 40 ?? 0f b6 49 1d 28 d1 80 c1 e7 88 48 } //5
		$a_01_1 = {66 0f 6f c8 66 0f 72 d1 18 66 0f 6f d1 66 0f 62 d0 66 0f 60 c8 66 0f 72 d0 10 66 0f 6e da 66 0f 6f e3 66 0f 76 ed 66 0f ef eb 66 0f 62 d8 66 0f 60 e0 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}