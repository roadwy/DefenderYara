
rule Trojan_Win32_AutoitInject_KAA_MTB{
	meta:
		description = "Trojan:Win32/AutoitInject.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {85 94 98 79 41 55 33 21 45 41 30 36 4d a8 ff 73 24 a7 3c f6 7a 12 f1 67 ac c1 93 e7 6b 43 ca 52 a6 ad } //00 00 
	condition:
		any of ($a_*)
 
}