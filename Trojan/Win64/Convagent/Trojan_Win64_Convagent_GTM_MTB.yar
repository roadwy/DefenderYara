
rule Trojan_Win64_Convagent_GTM_MTB{
	meta:
		description = "Trojan:Win64/Convagent.GTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {64 65 2e 0d ?? ?? ?? ?? 00 00 00 00 00 00 27 33 c6 ce 63 52 ?? 9d 63 52 ?? 9d 63 52 ?? 9d 6a 2a 3b 9d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}