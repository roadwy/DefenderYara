
rule Trojan_Win32_CryptInject_PE_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.PE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {33 d2 8b c1 6a 14 5e f7 f6 8a 44 15 90 01 01 30 81 90 01 03 00 41 81 f9 00 50 00 00 72 e4 33 d2 5e 33 c9 3b ca 8d 41 01 0f 45 c1 8d 48 01 81 f9 88 13 00 00 7c ed 42 81 fa e0 93 04 00 7c e2 90 00 } //01 00 
		$a_02_1 = {33 c9 3b ca 8d 41 01 0f 45 c1 8d 48 01 81 f9 90 01 02 00 00 7c 90 01 01 42 81 fa 90 01 03 00 7c 90 01 01 33 c9 56 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}