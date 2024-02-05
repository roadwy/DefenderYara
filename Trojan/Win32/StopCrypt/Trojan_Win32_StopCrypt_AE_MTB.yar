
rule Trojan_Win32_StopCrypt_AE_MTB{
	meta:
		description = "Trojan:Win32/StopCrypt.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 45 0c 01 45 fc 83 6d fc 02 8b 45 08 8b 4d 0c 31 08 } //02 00 
		$a_01_1 = {c1 e1 04 03 4d e0 33 c1 33 45 fc 89 45 0c 8b 45 0c 01 05 } //01 00 
		$a_01_2 = {81 ff 6e 27 87 01 7f 0d 47 81 ff f6 ea 2b 33 0f 8c } //00 00 
	condition:
		any of ($a_*)
 
}