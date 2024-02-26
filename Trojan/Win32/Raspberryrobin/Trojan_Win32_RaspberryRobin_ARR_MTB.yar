
rule Trojan_Win32_RaspberryRobin_ARR_MTB{
	meta:
		description = "Trojan:Win32/RaspberryRobin.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 11 c7 41 10 f7 06 00 00 c7 41 0c f7 06 00 00 c7 41 08 f7 06 00 00 c7 41 04 f7 06 00 00 8b 0d } //00 00 
	condition:
		any of ($a_*)
 
}