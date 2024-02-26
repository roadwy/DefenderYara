
rule Trojan_Win32_CryptInject_MBEP_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.MBEP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 53 00 00 f0 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 01 00 00 00 e9 00 00 00 04 31 53 00 04 31 53 00 dc 13 40 00 78 00 00 00 81 00 00 00 8c 00 00 00 8d 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4c 65 61 6e 69 6e 67 73 00 44 72 61 66 74 69 6e 65 73 73 00 00 54 65 72 72 61 72 69 69 61 } //00 00 
	condition:
		any of ($a_*)
 
}