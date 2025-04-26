
rule Trojan_Win32_GCleaner_PAFL_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.PAFL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 83 c0 46 89 45 fc 83 6d fc 0a 83 6d fc 3c 8b 45 08 8a 4d fc 03 c7 30 08 47 3b fb 7c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}