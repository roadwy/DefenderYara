
rule Trojan_Win64_Lazy_ETL_MTB{
	meta:
		description = "Trojan:Win64/Lazy.ETL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {30 84 0d a0 00 00 00 8d 41 88 30 84 0d a1 00 00 00 8d 41 89 30 84 0d a2 00 00 00 8d 41 8a 30 84 0d a3 00 00 00 8d 41 8b 30 84 0d a4 00 00 00 8d 41 8c 30 84 0d a5 00 00 00 8d 41 8d 30 84 0d a6 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}