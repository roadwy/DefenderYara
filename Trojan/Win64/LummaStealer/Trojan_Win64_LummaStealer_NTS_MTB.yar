
rule Trojan_Win64_LummaStealer_NTS_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.NTS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {43 0f b6 0c 01 01 c1 0f b6 c1 48 8b 4d ?? 8a 04 01 48 63 4d ec 48 8b 55 98 30 04 0a 44 8b 6d ec 41 83 c5 01 b8 fa 3d f7 cc 3d 62 fa 3e f1 0f 8e } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}