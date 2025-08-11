
rule Trojan_Win64_ClipBanker_SX_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 03 00 00 "
		
	strings :
		$a_03_0 = {ba 01 00 00 00 33 c9 ff 15 ?? ?? ?? ?? 48 8b d8 48 85 c0 74 ?? ff 15 ?? ?? ?? ?? 3d b7 00 00 00 75 ?? 48 8b cb } //10
		$a_03_1 = {b9 01 00 00 00 ff 15 ?? ?? ?? ?? 48 8b f8 48 85 c0 74 ?? 48 8b c8 ff 15 ?? ?? ?? ?? 48 85 c0 74 0c 48 8b cf 48 8b f0 ff 15 } //10
		$a_01_2 = {64 72 76 6f 70 74 69 6d 63 78 73 71 } //5 drvoptimcxsq
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_01_2  & 1)*5) >=25
 
}