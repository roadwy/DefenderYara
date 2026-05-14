
rule Trojan_Win64_Rhadamanthys_NSO_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.NSO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 c0 48 6b c0 64 48 c1 e8 20 8d 54 05 64 } //2
		$a_01_1 = {89 c0 48 c1 e8 1c 83 f8 0e 0f 87 } //3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3) >=5
 
}