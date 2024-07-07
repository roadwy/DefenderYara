
rule Trojan_Win32_FileCryptor_MS_MTB{
	meta:
		description = "Trojan:Win32/FileCryptor.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {30 04 33 81 ff 90 01 04 75 08 6a 00 ff 15 90 01 04 46 3b f7 90 18 e8 90 00 } //1
		$a_02_1 = {55 8b ec 51 a1 90 02 04 69 90 02 05 a3 90 02 04 c7 90 02 06 81 90 02 06 8b 90 02 03 01 90 02 14 5d c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}