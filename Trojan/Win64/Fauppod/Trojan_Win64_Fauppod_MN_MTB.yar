
rule Trojan_Win64_Fauppod_MN_MTB{
	meta:
		description = "Trojan:Win64/Fauppod.MN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 48 89 e5 48 83 ec 20 48 8b 05 86 8d 00 00 ff d0 48 8b 05 9d 8d 00 00 ff d0 ba 00 00 00 00 48 89 c1 48 8b 05 4c 8e 00 00 ff d0 48 8d 05 23 2c 00 00 48 89 c1 e8 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}