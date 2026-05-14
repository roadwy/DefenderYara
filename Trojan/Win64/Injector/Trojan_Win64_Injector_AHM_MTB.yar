
rule Trojan_Win64_Injector_AHM_MTB{
	meta:
		description = "Trojan:Win64/Injector.AHM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 63 d0 48 8b 45 20 48 01 d0 44 89 c2 31 ca 88 10 83 45 fc ?? 8b 45 fc 48 98 48 3b 45 28 72 } //30
		$a_03_1 = {0f b6 45 c7 c1 e0 ?? 89 c2 0f b6 45 c6 09 d0 89 c2 48 8b 45 10 89 10 e9 } //20
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}