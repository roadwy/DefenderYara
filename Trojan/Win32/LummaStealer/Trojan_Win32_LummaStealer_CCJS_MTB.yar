
rule Trojan_Win32_LummaStealer_CCJS_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.CCJS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 08 0f b6 44 04 28 ff 74 24 08 50 e8 ?? ?? ?? ?? 83 c4 08 8b 4c 24 08 88 44 0c 28 ff 44 24 08 8b 44 24 08 83 f8 } //5
		$a_03_1 = {89 44 24 08 8b 44 24 14 05 ?? ?? ?? ?? 89 44 24 04 8b 44 24 08 33 44 24 04 89 04 24 } //6
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*6) >=11
 
}