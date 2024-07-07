
rule Trojan_Win64_Zzinfor_EC_MTB{
	meta:
		description = "Trojan:Win64/Zzinfor.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 e2 7f 03 c2 83 e0 7f 2b c2 8b d0 48 63 4c 24 78 48 8b 44 24 70 88 14 08 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}