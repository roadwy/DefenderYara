
rule Trojan_Win32_Androm_AES_MTB{
	meta:
		description = "Trojan:Win32/Androm.AES!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {c1 fa 05 0f b6 45 ff c1 e0 03 0b d0 88 55 ff 0f b6 4d ff 2b 4d f8 88 4d ff 0f b6 55 ff 81 f2 84 00 00 00 88 55 ff 0f b6 45 ff 83 c0 4a 88 45 ff 0f b6 4d ff f7 d9 88 4d ff 0f b6 55 ff 83 c2 6f 88 55 ff } //00 00 
	condition:
		any of ($a_*)
 
}