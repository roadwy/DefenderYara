
rule Trojan_BAT_CryptInject_MBCR_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.MBCR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 00 79 00 73 00 74 00 65 00 5f 00 6d 00 2e 00 52 00 65 00 66 00 6c 00 5f 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 41 00 73 00 5f 00 73 00 65 00 6d 00 62 00 6c 00 79 00 } //1 Syste_m.Refl_ection.As_sembly
		$a_01_1 = {4c 00 6f 00 5f 00 61 00 64 00 } //1 Lo_ad
		$a_01_2 = {47 00 65 00 5f 00 74 00 45 00 78 00 70 00 5f 00 6f 00 72 00 74 00 65 00 64 00 54 00 79 00 5f 00 70 00 65 00 73 00 } //1 Ge_tExp_ortedTy_pes
		$a_01_3 = {44 00 79 00 6e 00 5f 00 61 00 6d 00 5f 00 69 00 63 00 49 00 6e 00 76 00 5f 00 6f 00 6b 00 65 00 } //1 Dyn_am_icInv_oke
		$a_01_4 = {53 00 79 00 5f 00 73 00 74 00 65 00 6d 00 2e 00 44 00 65 00 6c 00 65 00 67 00 5f 00 61 00 74 00 65 00 } //1 Sy_stem.Deleg_ate
		$a_01_5 = {51 00 6a 00 7a 00 74 00 65 00 72 00 68 00 7a 00 72 00 62 00 } //1 Qjzterhzrb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}