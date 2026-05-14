
rule Trojan_Win64_Rhadamanthys_NRV_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.NRV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 01 d0 0f b6 08 48 8b 55 20 48 8b 45 f8 48 01 d0 44 89 c2 31 ca 88 10 48 83 45 f8 } //2
		$a_01_1 = {89 45 ac 8b 55 98 8b 45 ac 01 d0 89 45 98 8b 55 84 8b 45 98 31 d0 89 45 84 8b 45 84 } //3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3) >=5
 
}