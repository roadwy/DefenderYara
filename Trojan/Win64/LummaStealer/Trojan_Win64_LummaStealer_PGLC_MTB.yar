
rule Trojan_Win64_LummaStealer_PGLC_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.PGLC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c1 30 d1 20 c1 44 20 c3 20 d0 08 d8 89 ca 30 c2 ba ?? ?? ?? ?? bb ?? ?? ?? ?? 0f 45 d3 8b 6f ?? 84 c0 89 d0 0f 45 c3 89 ac 24 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}