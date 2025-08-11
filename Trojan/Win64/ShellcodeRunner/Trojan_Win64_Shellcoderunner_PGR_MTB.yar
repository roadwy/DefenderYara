
rule Trojan_Win64_Shellcoderunner_PGR_MTB{
	meta:
		description = "Trojan:Win64/Shellcoderunner.PGR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 fc 48 8b 45 10 48 01 d0 0f b6 00 0f be c0 8d 50 ec 89 d0 c1 f8 ?? c1 e8 ?? 01 c2 0f b6 d2 29 c2 89 d1 8b 55 fc 48 8b 45 10 48 01 d0 89 ca 88 10 83 45 fc ?? 8b 45 fc 3b 45 18 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}