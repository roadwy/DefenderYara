
rule Trojan_Win32_LummaStealer_CRIT_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.CRIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6f 73 5f 63 35 37 36 78 65 64 72 79 70 74 2e 65 6e 63 72 79 35 37 36 78 65 64 70 74 65 64 5f 6b 65 79 } //1 os_c576xedrypt.encry576xedpted_key
		$a_01_1 = {4c 75 6d 35 37 36 78 65 64 6d 61 43 32 2c 20 42 75 69 6c 64 20 32 30 32 33 33 31 30 31 } //1 Lum576xedmaC2, Build 20233101
		$a_01_2 = {4c 49 44 28 4c 75 35 37 36 78 65 64 6d 6d 61 20 49 44 29 } //1 LID(Lu576xedmma ID)
		$a_01_3 = {50 68 79 73 35 37 36 78 65 64 69 63 61 6c 20 49 6e 73 35 37 36 78 65 64 74 61 6c 6c 65 64 20 4d 65 6d 6f 72 35 37 36 78 65 64 79 3a } //1 Phys576xedical Ins576xedtalled Memor576xedy:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}