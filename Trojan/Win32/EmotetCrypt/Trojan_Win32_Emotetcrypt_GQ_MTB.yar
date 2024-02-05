
rule Trojan_Win32_Emotetcrypt_GQ_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.GQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b df 0f af de 2b dd 43 43 0f af d9 2b f1 03 54 24 2c 03 c3 8d 04 70 2b 05 90 01 04 c1 e1 02 03 05 90 01 04 6a 04 5e 2b f1 0f af 35 90 01 04 83 ee 0c 0f af f7 8d 04 82 8a 0c 06 8b 44 24 20 30 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}