
rule Trojan_Win32_NSISInject_ETC_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.ETC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c4 0c 6a 40 68 00 30 00 00 68 90 01 04 56 ff 15 90 01 04 53 6a 01 bb 90 01 04 8b f8 53 57 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}