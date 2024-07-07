
rule Trojan_Win32_VidarCrypt_PAE_MTB{
	meta:
		description = "Trojan:Win32/VidarCrypt.PAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {29 45 80 8b 45 80 8b 4d 70 d3 e8 89 45 74 8b 85 68 ff ff ff 01 45 74 8b 75 80 8b 4d 84 03 4d 80 c1 e6 90 01 01 03 b5 70 ff ff ff 33 f1 90 00 } //1
		$a_01_1 = {33 c6 2b f8 ff 8d 78 ff ff ff 89 bd 7c ff ff ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}