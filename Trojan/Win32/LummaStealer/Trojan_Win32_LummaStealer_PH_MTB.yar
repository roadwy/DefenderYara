
rule Trojan_Win32_LummaStealer_PH_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.PH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {59 8b 14 98 8b 44 24 ?? 8b 48 08 8b 44 24 ?? 8a 04 01 8d 4c 24 ?? 30 82 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win32_LummaStealer_PH_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.PH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c0 8b 04 85 ?? ?? ?? ?? b9 ?? ?? ?? ?? 33 0d ?? ?? ?? ?? 01 c8 40 } //3
		$a_03_1 = {80 38 ef 75 ?? 80 78 01 bb 75 ?? 80 78 02 bf } //1
		$a_03_2 = {0f b6 5d 00 53 e8 ?? ?? ?? ?? 83 c4 04 85 c0 74 ?? 45 90 90 90 90 90 90 90 90 90 90 90 90 } //1
		$a_01_3 = {0f b6 d2 c1 e1 05 81 e1 e0 7f 00 00 31 d1 0f b7 94 4e 72 92 02 00 89 c7 81 e7 ff 7f 00 00 66 89 94 7e 72 92 01 00 89 da 42 66 89 84 4e 72 92 02 00 45 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*3) >=4
 
}