
rule Trojan_Win32_CobaltCrypt_VC_MTB{
	meta:
		description = "Trojan:Win32/CobaltCrypt.VC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {eb 00 31 0d 90 01 04 c7 05 90 02 40 a1 90 01 04 01 05 90 01 04 8b ff a1 90 01 04 8b 0d 90 01 04 89 08 90 00 } //1
		$a_03_1 = {89 08 5f 5d 90 09 28 00 31 0d 90 01 04 c7 05 90 02 40 a1 90 01 04 01 05 90 01 04 8b ff a1 90 01 04 8b 0d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}