
rule Trojan_BAT_CryptInject_MBET_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.MBET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 72 36 02 00 70 0d 16 0c 06 07 09 28 90 01 01 3b 00 06 2d 09 08 17 58 0c 08 1f 64 32 ed 90 00 } //01 00 
		$a_01_1 = {44 00 4e 00 37 00 34 00 36 00 35 00 35 00 32 00 42 00 31 00 36 00 33 00 } //01 00  DN746552B163
		$a_01_2 = {63 00 68 00 72 00 6f 00 6d 00 65 00 4e 00 6f 00 74 00 45 00 6e 00 63 00 6f 00 64 00 65 00 2e 00 65 00 78 00 65 00 } //01 00  chromeNotEncode.exe
		$a_01_3 = {77 ff b7 3f 09 1f 00 00 00 fa 25 33 00 16 c4 00 01 } //01 00 
		$a_01_4 = {5a 59 58 44 4e 47 75 61 72 64 65 72 } //00 00  ZYXDNGuarder
	condition:
		any of ($a_*)
 
}