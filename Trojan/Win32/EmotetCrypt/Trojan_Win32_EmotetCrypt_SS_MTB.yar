
rule Trojan_Win32_EmotetCrypt_SS_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.SS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 c1 0f b6 4c 24 11 8a 0c 11 30 08 ff 44 24 14 8b 44 24 14 3b 44 24 20 0f 8c a3 fb ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}