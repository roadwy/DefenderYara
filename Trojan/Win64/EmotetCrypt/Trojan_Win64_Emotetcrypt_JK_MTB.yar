
rule Trojan_Win64_Emotetcrypt_JK_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.JK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 04 01 8b 4c 24 04 33 c8 8b c1 8b 0d 90 01 04 8b 14 24 03 d1 8b ca 8b 15 90 01 04 0f af 15 90 01 04 0f af 15 90 01 04 0f af 15 90 01 04 2b ca 2b 0d 90 01 04 2b 0d 90 01 04 8b 15 90 01 04 0f af 15 90 01 04 03 ca 48 63 c9 48 8b 54 24 28 88 04 0a e9 90 00 } //01 00 
		$a_01_1 = {7a 5e 67 66 66 30 49 47 4a 72 70 68 76 4c 6d 34 4c 58 4c 2b 41 41 62 68 24 58 4b 3f 3f 40 46 68 67 47 49 4f 3e 30 26 6a 52 74 24 5f 6a 4f 38 73 68 6b 24 44 5e 25 35 7a 78 3f 32 6c } //00 00  z^gff0IGJrphvLm4LXL+AAbh$XK??@FhgGIO>0&jRt$_jO8shk$D^%5zx?2l
	condition:
		any of ($a_*)
 
}