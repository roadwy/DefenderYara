
rule Trojan_Win32_Vidar_NNV_MTB{
	meta:
		description = "Trojan:Win32/Vidar.NNV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 f1 66 f5 8d ad ?? ?? ?? ?? 32 d3 80 c2 ?? f6 d2 66 0f be cc 1b ce 0f b7 cf 80 c2 e8 66 c1 d9 ?? d0 c2 80 c2 ?? f6 d2 32 da 89 04 14 } //5
		$a_01_1 = {46 54 69 4e 76 53 } //1 FTiNvS
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}