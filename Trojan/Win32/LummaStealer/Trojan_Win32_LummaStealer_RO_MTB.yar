
rule Trojan_Win32_LummaStealer_RO_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.RO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 14 24 c7 44 24 04 00 00 00 00 c7 44 24 08 00 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 14 04 00 00 00 c7 44 24 18 00 00 00 00 c7 44 24 1c 00 00 00 00 89 4c 24 20 89 44 24 24 ff 15 } //1
		$a_01_1 = {89 14 24 89 4c 24 04 89 44 24 08 c7 44 24 0c 00 30 00 00 c7 44 24 10 40 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}