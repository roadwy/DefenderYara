
rule Trojan_Win32_LummaStealer_PADL_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.PADL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {51 c7 04 24 f0 43 03 00 83 04 24 0d a1 78 07 47 00 0f af 04 24 05 c3 9e 26 00 a3 78 07 47 00 0f b7 05 7a 07 47 00 25 ff 7f 00 00 59 c3 } //1
		$a_01_1 = {30 04 1e 46 3b f7 7c e0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}