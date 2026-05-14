
rule Trojan_Win64_Rhadamanthys_GXV_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.GXV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 89 ca 41 f7 d2 45 0f af d1 41 83 e2 01 41 0f 94 c1 41 83 f8 0a 41 0f 9c c3 45 08 cb } //5
		$a_03_1 = {41 20 d8 45 08 d0 45 30 c8 41 80 f0 ?? 44 88 04 01 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}