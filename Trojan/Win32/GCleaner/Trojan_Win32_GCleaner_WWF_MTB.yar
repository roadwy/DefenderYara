
rule Trojan_Win32_GCleaner_WWF_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.WWF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b f8 31 3e 83 c3 04 83 c6 04 3b 5d cc 72 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}