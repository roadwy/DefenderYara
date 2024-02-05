
rule Trojan_Win32_SpyStealer_AS_MTB{
	meta:
		description = "Trojan:Win32/SpyStealer.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {0f b6 4d ac 83 f1 2f 88 4d ac 0f b6 55 ad 83 f2 5e 88 55 ad 0f b6 45 a8 83 f0 62 88 45 a8 } //00 00 
	condition:
		any of ($a_*)
 
}