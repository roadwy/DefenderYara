
rule Trojan_Win64_Convagent_RZ_MTB{
	meta:
		description = "Trojan:Win64/Convagent.RZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 c7 48 8b 75 10 48 c7 c1 ?? ?? ?? 00 48 c1 e9 03 f3 48 a5 48 8d 45 e8 48 83 ec 20 48 c7 c1 ?? ?? ?? 00 48 8b 55 10 4c 8b 45 10 49 89 c1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}