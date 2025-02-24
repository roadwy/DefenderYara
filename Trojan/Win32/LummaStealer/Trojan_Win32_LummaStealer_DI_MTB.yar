
rule Trojan_Win32_LummaStealer_DI_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.DI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_03_0 = {02 ca 8a 8c 0d ?? ?? ff ff } //10
		$a_03_1 = {30 0e ff c6 ?? ?? 0f 85 } //1
		$a_01_2 = {ff ff 30 0e e9 } //1
		$a_03_3 = {30 0e ff c6 ?? ?? e9 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=11
 
}