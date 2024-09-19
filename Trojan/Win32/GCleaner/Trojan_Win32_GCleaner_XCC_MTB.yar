
rule Trojan_Win32_GCleaner_XCC_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.XCC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 95 dc fb ff ff 8b 85 d8 fb ff ff 30 14 38 83 fb 0f 75 22 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}