
rule Trojan_Win32_CryptInject_DL_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {3d 8d cc 05 00 75 06 81 c1 fa 23 0a 00 40 3d 0f 7e 49 00 7c eb } //02 00 
		$a_03_1 = {3d 50 4f 02 00 75 06 89 0d 90 02 04 40 3d 6c 17 30 32 7c eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}