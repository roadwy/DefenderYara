
rule Trojan_Win32_EmotetCrypt_MV_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.MV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {f7 f1 8b 45 08 90 02 05 32 90 02 03 47 3b 90 02 03 88 90 02 05 90 18 8b 90 02 05 ff 90 02 03 8d 90 02 03 e8 90 02 04 59 33 90 02 03 8b 90 02 03 8b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}