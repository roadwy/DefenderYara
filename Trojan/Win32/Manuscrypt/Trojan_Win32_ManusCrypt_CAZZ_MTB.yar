
rule Trojan_Win32_ManusCrypt_CAZZ_MTB{
	meta:
		description = "Trojan:Win32/ManusCrypt.CAZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 f8 01 76 ?? 8a 11 30 54 08 ff 83 c0 ff 83 e8 01 74 0c 8a 54 08 01 30 14 08 83 e8 01 75 f4 8a 54 08 01 30 14 08 c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}