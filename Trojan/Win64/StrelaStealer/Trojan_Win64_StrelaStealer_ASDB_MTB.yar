
rule Trojan_Win64_StrelaStealer_ASDB_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.ASDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 29 c4 48 8d ac 24 80 00 00 00 31 c0 8b 0d a3 90 02 02 00 8b 15 a9 90 02 02 00 41 90 02 10 41 90 01 01 c0 90 02 04 41 81 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}