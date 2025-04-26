
rule Trojan_Win64_DCRat_H_MTB{
	meta:
		description = "Trojan:Win64/DCRat.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {f7 eb 03 d3 c1 fa ?? 8b c2 c1 e8 1f 03 d0 b8 ?? ?? ?? ?? 2a c2 0f be c0 6b c8 ?? 02 cb ff c3 41 30 48 ff 83 fb } //2
		$a_03_1 = {41 f7 e0 41 8b c0 2b c2 d1 ?? 03 c2 c1 e8 ?? 0f be c0 6b c8 ?? 41 0f b6 c0 41 ff c0 2a c1 04 39 41 30 41 ff 41 83 f8 } //4
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*4) >=6
 
}