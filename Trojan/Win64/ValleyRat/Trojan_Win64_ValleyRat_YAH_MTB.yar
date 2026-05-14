
rule Trojan_Win64_ValleyRat_YAH_MTB{
	meta:
		description = "Trojan:Win64/ValleyRat.YAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 0c 04 02 0c 2c 0f b6 c9 8a 04 0c 42 32 04 07 43 88 04 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}