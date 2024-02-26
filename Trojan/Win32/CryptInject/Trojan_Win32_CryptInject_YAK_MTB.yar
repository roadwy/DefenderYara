
rule Trojan_Win32_CryptInject_YAK_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.YAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 fe 10 27 00 00 7d 0b 8d 8d 90 01 04 51 6a 00 ff d7 46 81 fe cc 9c f4 1f 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}