
rule Trojan_Win64_KillProc_EB_MTB{
	meta:
		description = "Trojan:Win64/KillProc.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 8b 44 24 18 45 8a 0c 08 66 44 8b 54 24 26 66 44 0b 54 24 26 66 44 89 54 24 26 44 88 4c 24 24 48 8b 0c 24 48 89 4c 24 28 4c 8b 5c 24 08 4c 03 5c 24 48 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}