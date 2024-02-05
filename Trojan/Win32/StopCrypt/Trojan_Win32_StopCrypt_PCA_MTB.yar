
rule Trojan_Win32_StopCrypt_PCA_MTB{
	meta:
		description = "Trojan:Win32/StopCrypt.PCA!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c1 e8 05 03 45 e8 33 ce 33 c1 89 4d 08 89 45 f8 8b 45 f8 01 05 1c 55 8c 00 ff 75 f8 8d 45 f4 50 e8 } //01 00 
		$a_01_1 = {01 45 fc 83 6d fc 02 8b 45 08 8b 4d fc 31 08 } //00 00 
	condition:
		any of ($a_*)
 
}