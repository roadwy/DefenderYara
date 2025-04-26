
rule Trojan_Win64_PasswordStealer_BL_MTB{
	meta:
		description = "Trojan:Win64/PasswordStealer.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {42 0f b6 4c 00 04 8b 15 [0-04] 02 d0 32 d1 42 88 54 00 04 48 ff c0 48 83 f8 08 72 } //1
		$a_03_1 = {42 0f b6 04 01 2c ?? 42 88 04 01 48 ff c1 48 83 f9 ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}