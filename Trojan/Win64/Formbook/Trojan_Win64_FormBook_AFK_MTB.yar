
rule Trojan_Win64_FormBook_AFK_MTB{
	meta:
		description = "Trojan:Win64/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 8b c1 41 c1 f8 1f 41 83 e0 0f 44 03 c1 41 83 e0 f0 44 8b c9 45 2b c8 45 8b c1 46 0f b7 44 46 0c 41 33 d0 44 8b c1 66 42 89 54 40 10 ff c1 83 f9 37 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}