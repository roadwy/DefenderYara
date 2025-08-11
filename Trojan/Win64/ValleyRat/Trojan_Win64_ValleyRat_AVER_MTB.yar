
rule Trojan_Win64_ValleyRat_AVER_MTB{
	meta:
		description = "Trojan:Win64/ValleyRat.AVER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 48 8b 44 24 20 b9 ?? ?? ?? ?? 48 f7 f1 48 8b c2 48 8d 0d ?? ?? ?? ?? 0f b6 04 01 48 8b 4c 24 28 0f be 09 33 c8 8b c1 48 8b 4c 24 28 88 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}