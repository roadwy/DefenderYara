
rule Trojan_Win64_CryptInject_NIM_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.NIM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {6c 69 63 65 6e 73 65 20 6b 65 79 20 2d 3e } //1 license key ->
		$a_01_1 = {8d 41 9b 30 44 0d e7 48 ff c1 48 83 f9 05 72 f0 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}