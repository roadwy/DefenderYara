
rule Trojan_Win32_Zenpack_DA_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 d9 01 de 81 e6 ff 00 00 00 8b 1d 90 01 04 81 c3 9e f4 ff ff 89 1d 90 01 04 8b 5d 90 01 01 8b 4d 90 01 01 8a 0c 0b 8b 5d 90 01 01 32 0c 33 8b 75 90 01 01 8b 5d 90 01 01 88 0c 1e 8b 0d 90 01 04 81 c1 27 eb ff ff 89 0d 90 01 04 8b 4d 90 01 01 39 cf 8b 4d 90 01 01 89 90 01 02 89 90 01 02 89 90 01 02 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}