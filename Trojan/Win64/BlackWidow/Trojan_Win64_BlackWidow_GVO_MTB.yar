
rule Trojan_Win64_BlackWidow_GVO_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.GVO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 03 c2 48 c1 e8 04 48 6b c0 19 48 2b c8 48 8b 45 0f 0f b6 4c 0d 27 43 32 4c 10 ff 41 88 4c 00 ff 3b 5d 07 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}