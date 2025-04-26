
rule Trojan_Win32_LummaStealer_DK_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff ff 30 0e e9 90 09 05 00 8a 8c 0d } //10
		$a_03_1 = {ff ff 02 ca e9 90 09 0c 00 88 8c 1d ?? ?? ff ff 88 94 05 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}