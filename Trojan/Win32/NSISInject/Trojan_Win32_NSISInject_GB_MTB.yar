
rule Trojan_Win32_NSISInject_GB_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 07 c0 c8 03 32 82 90 01 04 6a 0c 88 07 8d 42 01 99 5f f7 ff 46 3b f1 72 90 09 07 00 8d bc 35 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}