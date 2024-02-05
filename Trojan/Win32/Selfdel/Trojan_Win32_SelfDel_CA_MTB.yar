
rule Trojan_Win32_SelfDel_CA_MTB{
	meta:
		description = "Trojan:Win32/SelfDel.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {68 d0 1d 00 10 cc 31 45 fc 57 55 0f 85 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 4d 75 74 65 78 57 } //01 00 
		$a_01_2 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}