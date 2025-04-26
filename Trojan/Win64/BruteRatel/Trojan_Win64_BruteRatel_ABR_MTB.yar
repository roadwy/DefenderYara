
rule Trojan_Win64_BruteRatel_ABR_MTB{
	meta:
		description = "Trojan:Win64/BruteRatel.ABR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff c9 8b 72 20 48 01 ee 8b 34 8e 48 01 ee 48 31 ff 48 31 c0 fc ac 84 c0 74 ?? c1 cf 0d 01 c7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}