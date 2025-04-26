
rule Trojan_Win32_GCleaner_ASGH_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.ASGH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 c6 30 08 83 fb 0f 75 } //5
		$a_03_1 = {81 fe 8e 40 00 00 7e 0c 81 bd ?? e3 ff ff d7 be f5 00 75 09 46 81 fe d2 7e 68 00 7c } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}