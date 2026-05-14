
rule Trojan_Win64_Rhadamanthys_NSH_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.NSH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {25 ff ff ff 7f 31 d2 89 05 ?? ?? 00 00 41 f7 f0 89 d0 48 83 c4 38 } //2
		$a_03_1 = {48 89 c1 48 8d 05 ?? ?? 00 00 44 89 ca c1 e8 04 c1 e2 05 44 29 ca 01 c2 89 c8 c1 e0 04 01 c1 } //3
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*3) >=5
 
}