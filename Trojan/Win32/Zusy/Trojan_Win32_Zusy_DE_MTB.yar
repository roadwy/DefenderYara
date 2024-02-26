
rule Trojan_Win32_Zusy_DE_MTB{
	meta:
		description = "Trojan:Win32/Zusy.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c6 83 f0 0a b9 e0 00 00 00 99 f7 f9 8b ca } //01 00 
		$a_01_1 = {8b 45 fc 33 db 8a 5c 30 ff 2b d9 83 eb 20 83 fb 20 } //00 00 
	condition:
		any of ($a_*)
 
}