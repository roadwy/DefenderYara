
rule Trojan_Win32_Hupigon_AB_MTB{
	meta:
		description = "Trojan:Win32/Hupigon.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 8a 88 90 01 04 88 4d ef 0f b6 45 ef 83 f0 47 88 45 ef 0f b6 45 ef f7 d8 88 45 ef 0f b6 45 ef 2d e8 00 00 00 88 45 ef 0f b6 45 ef f7 d8 90 00 } //01 00 
		$a_03_1 = {88 45 ef 0f b6 45 ef 83 f0 6f 88 45 ef 8b 45 f8 8a 4d ef 88 88 90 01 04 e9 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}