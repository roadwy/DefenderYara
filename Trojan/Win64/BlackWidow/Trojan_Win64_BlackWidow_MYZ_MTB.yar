
rule Trojan_Win64_BlackWidow_MYZ_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.MYZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 03 cd 48 f7 e1 48 c1 ea 04 48 8d 04 d2 48 03 c0 48 2b c8 49 0f af cb 8a 44 0c ?? 42 32 04 16 41 88 02 4d 03 d5 44 3b cb 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}