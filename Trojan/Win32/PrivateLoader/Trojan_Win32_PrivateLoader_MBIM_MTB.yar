
rule Trojan_Win32_PrivateLoader_MBIM_MTB{
	meta:
		description = "Trojan:Win32/PrivateLoader.MBIM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {74 00 65 00 6b 00 65 00 70 00 61 00 62 00 69 00 63 00 75 00 77 00 65 00 6c 00 75 00 79 00 61 00 6c 00 75 00 74 00 65 00 6a 00 6f 00 73 00 65 00 77 00 75 00 6b 00 00 00 72 69 62 61 79 69 77 75 78 65 64 75 68 6f 64 6f 72 6f 6b 00 74 61 63 75 6b 00 00 00 70 00 75 00 6c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}