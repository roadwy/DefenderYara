
rule Trojan_Win64_SalatStealer_ASLT_MTB{
	meta:
		description = "Trojan:Win64/SalatStealer.ASLT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {01 d0 0f b6 c0 89 85 b0 00 00 00 8b 85 bc 00 00 00 48 63 d0 48 8b 85 e0 00 00 00 48 01 d0 44 0f b6 00 8b 85 b0 00 00 00 48 98 0f b6 4c 05 a0 8b 85 bc 00 00 00 48 63 d0 48 8b 85 e0 00 00 00 48 01 d0 44 89 c2 31 ca 88 10 } //2
		$a_03_1 = {48 89 42 38 48 8b 85 d0 03 00 00 4c 8b 40 28 48 8b 85 d0 03 00 00 48 8b 00 48 8d 15 ?? ?? ?? ?? 48 89 c1 41 ff d0 48 8b 95 d0 03 00 00 48 89 42 40 48 8b 85 d0 03 00 00 4c 8b 40 28 48 8b 85 d0 03 00 00 48 8b 00 48 8d 15 ?? ?? ?? ?? 48 89 c1 41 ff d0 48 8b 95 d0 03 00 00 48 89 42 48 48 8b 85 d0 03 00 00 4c 8b 40 28 48 8b 85 d0 03 00 00 48 8b 00 48 8d 15 ?? ?? ?? ?? 48 89 c1 41 ff d0 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}