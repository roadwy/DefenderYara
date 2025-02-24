
rule Trojan_Win32_LummaStealer_DJ_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.DJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {30 0e ff c6 e9 90 09 07 00 8a 8c 0d ?? ?? ff ff } //10
		$a_01_1 = {ff ff 02 ca e9 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}