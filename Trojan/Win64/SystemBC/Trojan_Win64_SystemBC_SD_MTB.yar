
rule Trojan_Win64_SystemBC_SD_MTB{
	meta:
		description = "Trojan:Win64/SystemBC.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 63 c9 48 c1 e1 02 48 01 ca 33 45 30 89 02 83 45 e4 01 8b 45 e4 48 63 d0 48 8b 45 d8 48 c1 e8 02 48 39 c2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}