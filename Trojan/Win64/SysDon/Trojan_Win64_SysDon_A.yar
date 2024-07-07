
rule Trojan_Win64_SysDon_A{
	meta:
		description = "Trojan:Win64/SysDon.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 89 5c 24 90 01 01 48 89 7c 24 90 01 01 e8 be 01 00 00 48 8b 8d 90 01 02 00 00 8b d8 e8 c4 34 00 00 48 83 a5 78 03 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}