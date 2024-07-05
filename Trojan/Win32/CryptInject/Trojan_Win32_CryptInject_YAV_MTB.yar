
rule Trojan_Win32_CryptInject_YAV_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.YAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {56 50 53 e8 01 00 00 00 cc } //01 00 
		$a_01_1 = {58 89 c3 40 2d 00 a0 26 00 2d 00 82 0c 10 05 f7 81 0c 10 80 3b cc } //0a 00 
		$a_01_2 = {85 c9 74 0a 31 06 01 1e 83 c6 04 49 eb } //0a 00 
		$a_01_3 = {e8 00 00 00 00 58 05 58 00 00 00 80 38 e9 75 13 } //00 00 
		$a_00_4 = {5d 04 00 00 aa 88 06 80 5c 29 00 00 ab 88 06 80 00 00 01 00 08 00 13 00 af 01 4b 65 79 4c } //6f 67 
	condition:
		any of ($a_*)
 
}