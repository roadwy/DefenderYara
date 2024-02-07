
rule Trojan_Win32_NSISInject_DA_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 45 e0 00 00 00 00 c7 04 24 00 00 00 00 c7 44 24 04 00 a3 e1 11 c7 44 24 08 00 30 00 00 c7 44 24 0c 04 00 00 00 89 45 dc ff 15 } //01 00 
		$a_81_1 = {43 3a 5c 78 61 6d 70 70 5c 68 74 64 6f 63 73 5c 4c 6f 63 74 } //00 00  C:\xampp\htdocs\Loct
	condition:
		any of ($a_*)
 
}