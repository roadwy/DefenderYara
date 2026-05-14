
rule Trojan_Win64_Mofngoloader_AMG_MTB{
	meta:
		description = "Trojan:Win64/Mofngoloader.AMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 4c 24 28 48 03 c8 48 8b c1 0f be 00 89 04 24 33 d2 48 8b 44 24 08 b9 05 00 00 00 48 f7 f1 48 8b c2 48 8d 0d 8a 5f 03 00 0f be 04 01 8b 0c 24 33 c8 8b c1 48 8b 4c 24 08 48 8b 54 24 20 48 03 d1 48 8b ca 88 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}