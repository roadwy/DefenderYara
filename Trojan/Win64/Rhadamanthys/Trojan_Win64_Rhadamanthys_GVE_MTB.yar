
rule Trojan_Win64_Rhadamanthys_GVE_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.GVE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 8d 42 01 48 83 fa 0c 48 8d 54 1a 01 4c 0f 43 c2 45 89 c0 45 0f b6 04 08 44 30 84 04 81 00 00 00 48 8d 04 16 48 ff c0 eb ad } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}