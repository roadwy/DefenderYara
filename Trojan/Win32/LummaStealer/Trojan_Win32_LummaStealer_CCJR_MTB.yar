
rule Trojan_Win32_LummaStealer_CCJR_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.CCJR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 04 24 0f b6 44 ?? 04 ff 34 24 50 e8 ?? ?? ?? ?? 83 c4 08 8b 0c 24 88 44 0c 04 ff ?? 24 8b 04 24 83 f8 } //5
		$a_03_1 = {21 d1 f7 d1 01 c8 8b 0c 24 8b 54 24 ?? 89 ce f7 d6 09 d6 01 f1 29 c8 } //6
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*6) >=11
 
}