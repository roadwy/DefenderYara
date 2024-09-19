
rule Trojan_Win32_GCleaner_ROE_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.ROE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 85 f4 fb ff ff 8a 8d f8 fb ff ff 03 c6 30 08 83 fb 0f 75 16 57 8d 85 fc fb ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}