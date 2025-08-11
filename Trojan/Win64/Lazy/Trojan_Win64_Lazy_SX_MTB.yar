
rule Trojan_Win64_Lazy_SX_MTB{
	meta:
		description = "Trojan:Win64/Lazy.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 45 10 48 8b 48 48 8b 45 fc 48 63 d0 48 89 d0 48 01 c0 48 01 d0 48 c1 e0 03 48 01 c8 48 8b 00 48 8b 55 18 48 89 c1 e8 ?? ?? ?? ?? 85 c0 75 24 48 8b 45 10 48 8b 48 48 8b 45 fc 48 63 d0 48 89 d0 48 01 c0 48 01 d0 48 c1 e0 03 48 01 c8 48 8b 40 08 eb 19 } //20
		$a_03_1 = {8b 85 2c 04 00 00 48 98 0f b6 44 05 a0 0f b6 c8 8b 85 2c 04 00 00 01 c0 48 63 d0 48 8b 85 10 04 00 00 48 01 d0 41 89 c8 48 8d 15 ?? ?? ?? ?? 48 89 c1 e8 ?? ?? ?? ?? 83 85 2c 04 00 00 01 83 bd 2c 04 00 00 0f 7e } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}