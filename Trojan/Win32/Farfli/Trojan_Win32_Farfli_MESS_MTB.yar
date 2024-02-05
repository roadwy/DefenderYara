
rule Trojan_Win32_Farfli_MESS_MTB{
	meta:
		description = "Trojan:Win32/Farfli.MESS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {20 69 6e 20 44 4f 53 20 6d 6f 64 65 2e 0d 0d 0a 24 90 01 07 ce 11 3d fa 8a 70 53 a9 8a 70 53 a9 8a 70 53 a9 49 7f 0e a9 80 70 53 a9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}