
rule Trojan_Win64_FormBook_ABFF_MTB{
	meta:
		description = "Trojan:Win64/FormBook.ABFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c1 0f b6 0c 10 41 8b 52 ?? 41 89 4a ?? 41 0f b6 42 ?? 49 8b 4a ?? 30 04 0a 41 ff 42 ?? 41 8b 82 ?? ?? ?? ?? 41 39 42 } //5
		$a_03_1 = {ff c2 49 ff c0 ?? ?? ?? ?? ?? 49 83 c1 02 80 f1 ?? 41 88 48 ff 3b 97 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}