
rule Trojan_Win32_CryptInject_DQ_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.DQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 4e 8b 06 8b d0 4f 46 8b 07 33 c2 47 46 8a c4 ff 0c 24 aa 58 8b d0 85 c0 75 08 } //01 00 
		$a_01_1 = {6a 00 ff 75 08 6a 00 6a 00 68 00 00 00 80 68 00 00 00 80 68 00 00 00 80 68 00 00 00 80 68 00 00 cf 00 } //00 00 
	condition:
		any of ($a_*)
 
}