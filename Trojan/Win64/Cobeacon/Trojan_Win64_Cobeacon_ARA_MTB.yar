
rule Trojan_Win64_Cobeacon_ARA_MTB{
	meta:
		description = "Trojan:Win64/Cobeacon.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 48 8b c1 49 f7 f1 42 0f b6 04 12 42 30 04 01 48 ff c1 48 3b cf 72 e7 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}