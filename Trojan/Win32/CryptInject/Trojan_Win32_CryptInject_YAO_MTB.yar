
rule Trojan_Win32_CryptInject_YAO_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.YAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b df 69 ff 63 fa 00 00 8b ca 83 e1 07 d3 eb 81 f7 71 20 85 94 30 1c 02 42 3b d6 72 e3 } //00 00 
	condition:
		any of ($a_*)
 
}