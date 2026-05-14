
rule Trojan_Win64_Rhadamanthys_NSJ_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.NSJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e2 05 31 d0 89 05 ?? ?? 00 00 48 8d 1b 48 89 e4 48 c1 e8 1c 83 f8 0e } //2
		$a_01_1 = {89 c2 c1 e2 0d 31 d0 89 c2 c1 ea 11 31 d0 4d } //3
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*3) >=5
 
}