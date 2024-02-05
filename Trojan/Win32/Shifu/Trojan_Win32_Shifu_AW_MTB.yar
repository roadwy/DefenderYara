
rule Trojan_Win32_Shifu_AW_MTB{
	meta:
		description = "Trojan:Win32/Shifu.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b ca 2b c8 83 e9 2b 8d 79 ea 81 ff 5e 02 00 00 76 07 8b c8 2b ca 83 e9 4b 83 f9 09 74 1e 83 f9 0c 74 0a 8d 3c 09 2b f8 83 ef 26 eb 1d 8d 04 cd 00 00 00 00 8b f8 8b c2 2b c7 eb 10 0f b6 d0 8d 54 0a 08 0f b7 fa 2b f8 03 f9 8b c7 83 ee 01 75 af } //00 00 
	condition:
		any of ($a_*)
 
}