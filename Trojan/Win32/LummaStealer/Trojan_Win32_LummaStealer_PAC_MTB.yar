
rule Trojan_Win32_LummaStealer_PAC_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.PAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c2 8d 34 17 8b ca 83 e0 7f 83 e1 1f 8a 1c 28 32 99 ?? ?? ?? ?? 32 99 ?? ?? ?? ?? 32 da 8b 54 24 38 03 d6 88 1e 8d 42 ff 25 7f 00 00 80 } //3
		$a_01_1 = {8b 54 24 20 c0 e8 02 42 32 c8 89 54 24 20 88 0e 81 fa 00 01 00 00 7c 98 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}