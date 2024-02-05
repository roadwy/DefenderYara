
rule Trojan_Win32_NSISInject_psyA_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.psyA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {56 e8 f8 2e 00 00 56 ff 15 a0 80 40 00 8d 74 06 01 38 1e 75 eb } //00 00 
	condition:
		any of ($a_*)
 
}