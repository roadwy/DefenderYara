
rule Trojan_Win32_NSISInject_D_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 45 fc 00 00 00 00 68 00 a3 e1 11 6a 01 ff 15 } //01 00 
		$a_81_1 = {43 3a 5c 78 61 6d 70 70 5c 68 74 64 6f 63 73 5c 4c 6f 63 74 } //00 00  C:\xampp\htdocs\Loct
	condition:
		any of ($a_*)
 
}