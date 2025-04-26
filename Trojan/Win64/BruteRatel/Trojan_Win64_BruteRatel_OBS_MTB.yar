
rule Trojan_Win64_BruteRatel_OBS_MTB{
	meta:
		description = "Trojan:Win64/BruteRatel.OBS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 98 48 8d 0c c5 00 00 00 00 48 8d 05 1d 11 01 00 48 8b 04 01 48 39 c2 75 14 8b 45 fc 48 63 d0 48 8b 45 f0 48 01 d0 8b 55 f8 88 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}