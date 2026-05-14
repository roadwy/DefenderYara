
rule Trojan_Win64_Rhadamanthys_NSE_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.NSE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 f1 48 89 c2 48 8d 05 ?? ?? 00 00 31 c1 89 c8 31 d0 eb } //3
		$a_01_1 = {48 0f af d1 48 c1 ea 24 8d 14 92 c1 e2 02 29 d0 83 f8 13 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}