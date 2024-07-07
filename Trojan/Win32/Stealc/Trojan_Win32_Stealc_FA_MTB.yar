
rule Trojan_Win32_Stealc_FA_MTB{
	meta:
		description = "Trojan:Win32/Stealc.FA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e1 04 89 54 24 18 03 cd 8d 14 06 33 ca 89 4c 24 10 89 3d 90 02 04 8b 44 24 18 01 05 90 02 04 a1 90 02 04 89 44 24 34 89 7c 24 18 8b 44 24 34 01 44 24 18 8b 44 24 10 33 44 24 18 89 44 24 18 8b 4c 24 18 89 4c 24 18 8b 44 24 18 29 44 24 14 8b 44 24 14 8b c8 c1 e1 04 03 cb 81 3d 90 02 04 be 01 00 00 89 4c 24 10 8d 3c 06 75 90 00 } //1
		$a_01_1 = {33 cf 89 4c 24 10 8b 44 24 18 31 44 24 10 8b 44 24 10 29 44 24 1c a1 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}