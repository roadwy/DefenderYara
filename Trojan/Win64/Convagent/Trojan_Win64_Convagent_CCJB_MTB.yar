
rule Trojan_Win64_Convagent_CCJB_MTB{
	meta:
		description = "Trojan:Win64/Convagent.CCJB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 3b 66 10 76 ?? 55 48 89 e5 48 83 ec 30 48 8d 05 ?? ?? ?? ?? bb ?? 01 00 00 e8 ?? ?? ?? ?? 90 90 48 85 c9 74 ?? 31 c0 31 db 48 89 d9 48 83 c4 30 5d c3 48 8d 0d ?? ?? ?? ?? bf 01 00 00 00 31 f6 49 c7 c0 ff ff ff ff e8 ?? ?? ?? ?? 48 83 c4 30 5d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}