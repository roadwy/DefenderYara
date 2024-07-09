
rule Trojan_Win64_Latrodectus_DA_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 63 4b 7c 8b 43 64 35 23 31 01 00 c1 ea 10 29 43 18 48 8b 05 ?? ?? ?? ?? 88 14 01 41 8b d0 ff 43 7c 48 8b 05 ?? ?? ?? ?? c1 ea 08 48 63 48 7c 48 8b 80 a0 00 00 00 88 14 01 } //1
		$a_03_1 = {48 89 c8 48 f7 e2 48 c1 ea 02 48 89 d0 48 c1 e0 02 48 01 d0 48 01 c0 48 01 d0 48 01 c0 48 29 c1 48 89 ca 0f b6 84 15 ?? ?? ?? ?? 44 31 c8 41 88 00 48 83 85 ?? ?? ?? ?? 01 48 8b 85 ?? ?? ?? ?? 48 39 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}