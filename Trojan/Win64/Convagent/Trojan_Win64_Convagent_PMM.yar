
rule Trojan_Win64_Convagent_PMM{
	meta:
		description = "Trojan:Win64/Convagent.PMM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 85 4f 03 00 00 0f b6 85 4f 03 00 00 83 f0 01 84 c0 74 0a bb 01 00 00 00 e9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}