
rule Trojan_Win64_BigpipeLoader_RPY_MTB{
	meta:
		description = "Trojan:Win64/BigpipeLoader.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 ec 29 45 fc 48 8b 45 10 48 8b 00 8b 55 ec 89 d2 48 01 c2 48 8b 45 10 48 89 10 48 8b 45 18 8b 10 8b 45 ec 01 c2 48 8b 45 18 89 10 83 7d fc 00 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}