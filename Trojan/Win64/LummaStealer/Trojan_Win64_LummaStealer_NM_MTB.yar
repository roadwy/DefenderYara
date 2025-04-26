
rule Trojan_Win64_LummaStealer_NM_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 c9 48 89 4c 24 30 89 4c 24 38 49 ba 70 d1 54 54 6f 07 a8 e8 48 21 4c 24 20 44 8d 49 0c 8d 51 01 48 8b c8 48 8b c7 4c 8d 44 24 30 ff 15 ff 73 03 00 } //3
		$a_01_1 = {85 c0 74 08 8a 44 24 38 24 01 eb 06 32 c0 eb 02 b0 01 48 8b 4c 24 40 48 33 cc e8 c8 c2 fa ff 48 8b 5c 24 60 48 83 c4 50 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}