
rule Trojan_Win32_LummaStealer_PGLS_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.PGLS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c7 f7 75 ?? 8b 45 ?? 8a 04 02 32 c1 8b 4d ?? 32 01 8b 4d ?? 88 04 31 46 81 fb ?? ?? ?? ?? 0f 82 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win32_LummaStealer_PGLS_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.PGLS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 34 ?? 56 50 e8 ?? ?? ?? ?? 83 c4 ?? 88 44 34 ?? 46 83 fe ?? 75 } //5
		$a_03_1 = {0f b6 44 1c ?? 53 50 e8 ?? ?? ?? ?? 83 c4 ?? 88 44 1c ?? 43 83 fb ?? 75 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}