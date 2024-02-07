
rule Trojan_Win32_Injector_MRTY_MTB{
	meta:
		description = "Trojan:Win32/Injector.MRTY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 39 34 36 33 33 38 62 65 31 33 33 33 39 33 33 64 31 31 39 33 66 33 33 33 39 36 39 36 } //00 00  f946338be1333933d1193f3339696
	condition:
		any of ($a_*)
 
}