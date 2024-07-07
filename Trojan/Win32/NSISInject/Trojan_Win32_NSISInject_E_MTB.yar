
rule Trojan_Win32_NSISInject_E_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 45 fc 00 00 00 00 6a 04 68 00 30 00 00 68 00 a3 e1 11 6a 00 ff 15 } //1
		$a_81_1 = {43 3a 5c 78 61 6d 70 70 5c 68 74 64 6f 63 73 5c 4c 6f 63 74 } //1 C:\xampp\htdocs\Loct
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}