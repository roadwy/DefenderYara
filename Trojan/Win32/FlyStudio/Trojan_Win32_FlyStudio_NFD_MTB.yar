
rule Trojan_Win32_FlyStudio_NFD_MTB{
	meta:
		description = "Trojan:Win32/FlyStudio.NFD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {8d 85 f4 fd ff ff 50 e8 bc 00 00 00 33 db 39 9e 90 01 04 75 13 8d 85 90 01 04 50 e8 ed 7c fe ff 90 00 } //01 00 
		$a_01_1 = {65 00 79 00 75 00 79 00 61 00 6e 00 2e 00 63 00 6f 00 6d 00 } //00 00  eyuyan.com
	condition:
		any of ($a_*)
 
}