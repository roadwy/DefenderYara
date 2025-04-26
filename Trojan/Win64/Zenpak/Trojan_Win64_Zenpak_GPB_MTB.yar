
rule Trojan_Win64_Zenpak_GPB_MTB{
	meta:
		description = "Trojan:Win64/Zenpak.GPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 89 e5 8a 45 0c 8a 4d 08 88 c2 02 15 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}