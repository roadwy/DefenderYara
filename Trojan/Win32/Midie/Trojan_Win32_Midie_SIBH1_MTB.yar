
rule Trojan_Win32_Midie_SIBH1_MTB{
	meta:
		description = "Trojan:Win32/Midie.SIBH1!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 90 01 01 00 00 8b d8 53 6a 00 ff 15 90 01 04 6a 00 8b f8 8d 45 90 01 01 50 53 57 56 ff 15 90 01 04 33 c9 85 db 74 90 01 01 8a 04 39 90 02 20 34 90 01 01 90 02 20 34 90 01 01 90 02 20 04 90 01 01 88 04 39 41 3b cb 72 eb 6a 00 6a 00 57 ff 15 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}