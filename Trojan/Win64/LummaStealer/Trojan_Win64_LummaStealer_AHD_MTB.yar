
rule Trojan_Win64_LummaStealer_AHD_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.AHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 83 ec 28 b9 ?? 00 00 00 e8 ?? ?? ?? ?? 49 89 c2 [0-0f] 48 85 c0 0f 84 ?? 01 00 00 48 b8 [0-0a] 48 ba [0-19] 49 89 02 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 49 89 [0-1e] 4c 89 d0 0f 1f 80 00 00 00 00 } //30
		$a_03_1 = {ff ff ff f6 21 88 01 ?? 8d [0-07] 48 83 c1 01 4c 39 c1 75 } //20
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}