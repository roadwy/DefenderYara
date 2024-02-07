
rule Trojan_BAT_Redline_GCV_MTB{
	meta:
		description = "Trojan:BAT/Redline.GCV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 00 4c 00 61 00 6e 00 67 00 7a 00 67 00 65 00 6e 00 4e 00 56 00 64 00 43 00 53 00 50 00 41 00 72 00 6d 00 6d 00 46 00 64 00 67 00 3d 00 3d 00 } //01 00  ALangzgenNVdCSPArmmFdg==
		$a_01_1 = {43 33 35 35 34 32 35 34 34 37 35 } //01 00  C3554254475
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_4 = {54 72 69 70 6c 65 44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //01 00  TripleDESCryptoServiceProvider
		$a_80_5 = {44 4f 53 4c 61 75 6e 63 68 65 72 2e 65 78 65 } //DOSLauncher.exe  00 00 
	condition:
		any of ($a_*)
 
}