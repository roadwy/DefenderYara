
rule Trojan_Win32_CryptInject_BL_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 ff 15 90 01 04 e8 90 01 04 30 04 33 81 ff 9b 0a 00 00 75 90 00 } //01 00 
		$a_02_1 = {69 c0 fd 43 03 00 05 c3 9e 26 00 81 3d 90 01 04 ac 10 00 00 56 a3 90 01 04 8b f0 75 90 01 01 ff 15 90 01 04 8b 4d 90 01 01 8b c6 c1 e8 10 33 cd 25 ff 7f 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}