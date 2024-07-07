
rule Trojan_Win32_VBKrypt_BC_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {64 8b 1d 30 00 00 00 8b 5b 08 8b 83 00 10 00 00 8b 0b 48 39 08 75 fb } //1
		$a_02_1 = {6a 00 ff d0 68 90 01 04 5a 31 c9 81 c9 90 01 04 8b 34 0a 89 34 08 81 34 08 90 01 04 83 c1 fc 7d ee ff d0 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}