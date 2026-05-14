
rule Trojan_Win64_Rhadamanthys_NTF_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.NTF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {b9 64 00 00 00 ff d6 b9 64 00 00 00 ff d6 b9 64 00 00 00 ff d6 b9 } //2
		$a_03_1 = {48 69 c0 e8 03 00 00 48 8b ?? ?? ?? 48 89 c2 48 09 ca 48 c1 ea 20 75 ?? 31 d2 f7 f1 48 3d } //3
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*3) >=5
 
}