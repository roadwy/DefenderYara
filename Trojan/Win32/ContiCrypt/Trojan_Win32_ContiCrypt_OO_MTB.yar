
rule Trojan_Win32_ContiCrypt_OO_MTB{
	meta:
		description = "Trojan:Win32/ContiCrypt.OO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f af c6 88 6d f2 b9 05 00 00 00 99 f7 f9 0f be 45 e9 8b 8d 70 ff ff ff 03 c3 0f be f2 33 c6 23 c8 } //1
		$a_01_1 = {33 14 e4 83 c4 04 81 e7 00 00 00 00 8b 3c e4 83 ec fc 31 f6 0b 34 e4 83 c4 04 31 db 8b 1c e4 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}