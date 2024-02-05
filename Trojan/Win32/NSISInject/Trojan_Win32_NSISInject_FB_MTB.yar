
rule Trojan_Win32_NSISInject_FB_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.FB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {83 c4 0c 8b f0 6a 40 68 00 30 00 00 68 90 01 04 57 ff 15 90 00 } //01 00 
		$a_03_1 = {88 04 3b 47 81 ff 90 01 04 72 90 01 01 6a 00 53 ff 15 90 01 04 5f 5e 33 c0 5b 8b e5 5d c2 10 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}