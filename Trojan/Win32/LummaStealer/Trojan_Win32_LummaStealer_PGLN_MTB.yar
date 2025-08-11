
rule Trojan_Win32_LummaStealer_PGLN_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.PGLN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 f7 75 ?? c0 e1 ?? 32 cb c0 e1 ?? 8a 04 3a c0 e8 ?? 32 c8 8b 45 ?? 88 0c 03 43 81 fb ?? ?? ?? ?? 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win32_LummaStealer_PGLN_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.PGLN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 85 54 ff ff ff 8b 8d 50 ff ff ff 8a 14 08 8b 85 54 ff ff ff 88 10 8b 85 54 ff ff ff 83 c0 01 89 85 54 ff ff ff 3b 85 4c ff ff ff 75 } //5
		$a_01_1 = {c1 e8 05 01 c1 66 89 ca 8b 45 84 66 89 10 8b 45 94 03 45 94 89 45 94 8b 45 88 33 45 8c 89 45 8c eb } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}