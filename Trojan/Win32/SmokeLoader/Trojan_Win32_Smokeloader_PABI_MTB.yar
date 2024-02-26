
rule Trojan_Win32_Smokeloader_PABI_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.PABI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 3c 8d 87 90 01 04 56 81 f1 6c 06 00 00 51 50 8b 44 24 34 05 d2 fe ff ff 35 dd 02 00 00 50 8d 83 76 fd ff ff 50 e8 90 01 04 83 c4 14 81 90 01 04 00 78 c6 00 00 77 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}