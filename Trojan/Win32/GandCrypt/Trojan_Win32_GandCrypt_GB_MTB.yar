
rule Trojan_Win32_GandCrypt_GB_MTB{
	meta:
		description = "Trojan:Win32/GandCrypt.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 fe 70 d2 14 00 7e 90 01 01 81 bd 6c ff ff ff 28 9b 1a 75 74 90 01 01 81 7d 90 01 02 2a 69 12 75 90 01 01 46 81 fe 01 3f 14 22 7c 90 01 01 a1 90 01 04 8b f7 05 3b 2d 0b 00 a3 90 01 04 81 fe 89 62 65 00 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}