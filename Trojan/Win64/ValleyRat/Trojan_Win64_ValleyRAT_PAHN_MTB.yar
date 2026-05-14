
rule Trojan_Win64_ValleyRAT_PAHN_MTB{
	meta:
		description = "Trojan:Win64/ValleyRAT.PAHN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 74 48 8b 45 00 48 01 d0 0f b6 00 8b 4d 74 48 8b 55 00 48 01 ca 32 45 7b 88 02 0f b6 45 fe 00 45 7b 83 45 74 01 8b 45 74 3b 45 14 72 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}