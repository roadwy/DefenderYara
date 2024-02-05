
rule Trojan_Win32_Midie_SIBJ1_MTB{
	meta:
		description = "Trojan:Win32/Midie.SIBJ1!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {76 6d 73 6c 6f 61 6e 62 2e 64 6c 6c } //01 00 
		$a_03_1 = {33 c9 85 db 74 90 01 01 8a 04 39 90 02 20 2c 90 01 01 90 02 20 04 90 01 01 90 02 20 88 04 39 41 3b cb 72 90 01 01 6a 00 57 6a 00 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}