
rule Trojan_Win64_Rhadamanthys_NTM_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.NTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 02 31 c1 48 8b 44 24 ?? 48 63 54 24 ?? 88 0c 10 8b 44 24 } //2
		$a_01_1 = {48 83 ec 28 89 ce 31 c9 31 d2 45 31 c0 45 31 c9 } //3
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*3) >=5
 
}