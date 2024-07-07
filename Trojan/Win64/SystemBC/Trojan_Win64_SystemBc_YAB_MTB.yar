
rule Trojan_Win64_SystemBc_YAB_MTB{
	meta:
		description = "Trojan:Win64/SystemBc.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 5d cc 03 5d ac 81 eb 67 2b 00 00 03 5d e8 2b d8 6a 00 e8 90 01 04 2b d8 8b 45 d8 31 18 6a 00 e8 90 01 04 ba 04 00 00 00 2b d0 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}