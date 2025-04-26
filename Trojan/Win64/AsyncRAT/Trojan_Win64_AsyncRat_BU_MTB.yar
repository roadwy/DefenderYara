
rule Trojan_Win64_AsyncRat_BU_MTB{
	meta:
		description = "Trojan:Win64/AsyncRat.BU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 c1 e1 08 48 01 ca 48 81 c2 ?? 00 00 00 44 8b 12 45 33 11 41 01 c2 49 81 f8 ?? ?? 00 00 44 89 d0 44 89 55 ?? 4c 89 45 ?? 89 45 cc 75 } //3
		$a_03_1 = {48 8b 45 e0 c7 05 ?? ?? ?? ?? ?? ?? 00 00 48 8b 4d f8 8a 14 01 4c 8b 45 e8 41 88 14 00 48 05 01 00 00 00 4c 8b 4d f0 4c 39 c8 48 89 45 e0 75 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}