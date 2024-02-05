
rule Trojan_Win32_Redline_BN_MTB{
	meta:
		description = "Trojan:Win32/Redline.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {0f be 14 32 31 d1 01 c8 88 c2 8b 45 0c 8b 4d f0 88 14 08 0f be 75 ef 8b 45 0c 8b 4d f0 0f be 14 08 29 f2 88 14 08 8b 45 f0 83 c0 01 89 45 f0 e9 } //00 00 
	condition:
		any of ($a_*)
 
}