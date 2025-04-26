
rule Trojan_Win32_LummaStealer_AMCV_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.AMCV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e0 3b 45 e4 0f 8d ?? ?? ?? ?? 8b 45 e8 8b 4d e0 c1 e1 02 8b 04 08 89 45 f8 69 45 f8 ?? ?? ?? ?? 89 45 f8 8b 45 f8 c1 e8 18 33 45 f8 89 45 f8 69 45 f8 90 1b 01 89 45 f8 69 45 ec 90 1b 01 89 45 ec 8b 45 f8 33 45 ec 89 45 ec 8b 45 e0 83 c0 01 89 45 e0 } //4
		$a_03_1 = {0f be 00 33 45 d8 89 45 d8 69 45 d8 ?? ?? ?? ?? 89 45 d8 8b 45 d8 33 45 ec 89 45 ec 8b 45 ec c1 e8 0d 33 45 ec 89 45 ec 69 45 ec 90 1b 00 89 45 ec 8b 45 ec c1 e8 0f 33 45 ec 89 45 ec 8b 45 ec 89 45 cc 8b 4d fc 31 e9 e8 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}