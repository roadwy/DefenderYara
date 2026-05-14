
rule Trojan_Win64_Rhadamanthys_NRW_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.NRW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 01 d0 44 89 c2 31 ca 88 10 48 83 45 f8 01 } //2
		$a_03_1 = {44 89 f2 4c 8b 44 24 30 4c 8b 54 24 28 48 89 c1 48 8d 05 ?? ?? ?? ?? 4c 8b 4c 24 20 31 c2 89 d0 48 8b 54 24 38 31 c8 } //3
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*3) >=5
 
}