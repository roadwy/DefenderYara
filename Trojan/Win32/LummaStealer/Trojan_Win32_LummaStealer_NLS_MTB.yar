
rule Trojan_Win32_LummaStealer_NLS_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.NLS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 91 6c 01 00 00 89 54 24 04 e8 48 04 03 00 0f b6 44 24 ?? 84 c0 74 10 8b 44 24 10 c7 80 ?? ?? ?? ?? 00 00 00 00 eb 04 8b 44 24 10 8b 80 ?? ?? ?? ?? 89 44 24 1c 83 c4 } //5
		$a_01_1 = {61 74 6f 6d 69 63 2e 51 53 59 5f 7a 72 68 } //1 atomic.QSY_zrh
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}