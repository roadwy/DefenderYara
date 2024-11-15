
rule Trojan_Win32_LummaStealer_NG_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c4 08 a3 1c 85 44 00 68 6c d4 6c e5 ff 35 14 85 44 00 e8 ?? ?? ?? ?? 83 c4 08 a3 20 85 44 00 68 5c 40 7d ec ff 35 14 85 44 00 } //3
		$a_03_1 = {a3 e8 74 44 00 ff 35 14 85 44 00 e8 ?? ?? ?? ?? 83 c4 04 0f b6 c0 8b 04 85 d0 52 44 00 b9 a4 bb 8b ae 33 0d d8 52 44 00 01 c1 41 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}