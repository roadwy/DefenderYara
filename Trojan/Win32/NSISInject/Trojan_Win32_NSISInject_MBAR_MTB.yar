
rule Trojan_Win32_NSISInject_MBAR_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.MBAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c1 99 6a 0c 5e f7 fe 8a 82 3c b2 40 00 30 04 19 41 3b cf 72 ea } //01 00 
		$a_01_1 = {83 c4 24 6a 40 68 00 30 00 00 57 53 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}