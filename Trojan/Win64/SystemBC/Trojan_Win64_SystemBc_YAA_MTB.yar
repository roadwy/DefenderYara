
rule Trojan_Win64_SystemBc_YAA_MTB{
	meta:
		description = "Trojan:Win64/SystemBc.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c2 81 c2 20 00 00 00 41 89 c0 45 89 c1 25 1f 00 00 00 89 c0 41 89 c2 46 8a 1c 11 48 8b 8d ?? ?? ?? ?? 42 8a 1c 09 44 28 db 42 88 1c 09 8b 45 94 39 c2 89 95 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}