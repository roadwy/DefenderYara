
rule Trojan_Win32_RedLine_RDDG_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 c1 eb 37 4b 43 66 2b f9 66 c1 c1 69 66 c1 df bb } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}