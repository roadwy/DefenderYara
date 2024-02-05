
rule Trojan_Win64_Qakbot_LL_MTB{
	meta:
		description = "Trojan:Win64/Qakbot.LL!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 a1 30 00 00 00 56 57 8b 40 0c 8b 78 14 85 ff } //00 00 
	condition:
		any of ($a_*)
 
}