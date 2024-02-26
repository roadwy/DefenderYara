
rule Trojan_Win32_CryptInject_AB_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {69 c0 fd 43 03 00 05 c3 9e 26 00 56 a3 90 01 04 0f b7 35 90 01 04 81 e6 ff 7f 00 00 81 3d 90 01 04 e7 08 00 00 90 00 } //01 00 
		$a_03_1 = {81 fb 85 02 00 00 75 90 01 01 56 56 56 56 56 ff 15 90 01 04 56 56 56 56 ff 15 90 01 04 e8 90 01 04 30 04 2f 81 fb 91 05 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}