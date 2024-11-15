
rule Trojan_Win32_LummaStealer_DDI_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.DDI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 c1 33 32 0c 1a fe c1 88 0c 1a 43 83 fb 14 } //5
		$a_03_1 = {89 d7 31 c7 21 d0 81 f7 c2 00 00 00 8d 04 47 32 84 16 ?? ?? ?? ?? 04 36 88 84 16 ?? ?? ?? ?? 42 83 c1 02 83 fa 15 75 } //4
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*4) >=9
 
}