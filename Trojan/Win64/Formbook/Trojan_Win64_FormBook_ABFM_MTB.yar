
rule Trojan_Win64_FormBook_ABFM_MTB{
	meta:
		description = "Trojan:Win64/FormBook.ABFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 89 c1 f2 45 0f 38 f1 c8 44 8b 54 24 08 45 31 ca f2 45 0f 38 f1 ca 45 89 ca 41 c1 ea 08 45 89 cb 41 c1 eb 10 45 31 d3 45 89 ca 41 c1 ea 18 42 0f b6 34 01 44 31 d6 44 31 de 44 31 ce 42 88 34 02 49 ff c0 } //5
		$a_03_1 = {4c 8b 06 4d 01 f0 42 30 14 01 48 ff c1 ?? ?? 49 01 c6 ff 44 24 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}