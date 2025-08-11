
rule Trojan_Win64_Bodegun_ABD_MTB{
	meta:
		description = "Trojan:Win64/Bodegun.ABD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {80 f1 55 48 8d 7f 01 49 3b d0 73 ?? 48 8d 42 01 48 89 45 bf 48 8d 45 af 49 83 f8 0f 48 0f 47 45 af 88 0c 10 c6 44 10 01 00 eb 0d 44 0f b6 c9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}