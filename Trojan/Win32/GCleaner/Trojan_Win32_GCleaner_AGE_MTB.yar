
rule Trojan_Win32_GCleaner_AGE_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.AGE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f 28 0d b0 98 43 00 66 0f ef c8 0f 11 09 0f 1f 40 00 80 34 08 2e 40 83 f8 1c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}