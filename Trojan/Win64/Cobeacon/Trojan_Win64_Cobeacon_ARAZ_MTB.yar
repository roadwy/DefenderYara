
rule Trojan_Win64_Cobeacon_ARAZ_MTB{
	meta:
		description = "Trojan:Win64/Cobeacon.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 c0 44 0f b6 44 05 10 45 30 43 ff 83 c6 ff 75 c1 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}