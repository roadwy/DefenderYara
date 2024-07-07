
rule Trojan_Win32_LummaStealer_MA_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 dc 8b 00 89 45 d0 83 45 dc 04 8b 45 d4 89 45 d8 8b 45 d8 83 e8 04 89 45 d8 33 c0 89 45 ec 33 c0 89 45 b4 33 c0 89 45 b0 8b 45 e0 8b 10 } //5
		$a_03_1 = {2b d8 81 c3 90 01 04 8b 45 d4 31 18 83 45 ec 04 83 45 d4 04 8b 45 ec 3b 45 d0 72 90 00 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}