
rule Trojan_Win64_IcedID_RDB_MTB{
	meta:
		description = "Trojan:Win64/IcedID.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 41 83 c1 20 49 83 c2 02 41 c1 c0 07 41 0f b7 c1 ff c3 44 33 c0 45 0f b7 0a 66 45 85 c9 } //2
		$a_01_1 = {45 33 c0 48 8d 41 01 41 8a d0 02 11 42 30 14 00 49 ff c0 49 83 f8 19 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}