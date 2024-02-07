
rule Trojan_Win32_Netvat_C{
	meta:
		description = "Trojan:Win32/Netvat.C,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 08 00 06 00 00 04 00 "
		
	strings :
		$a_01_0 = {39 75 10 7c 1a 8b 45 08 8d 0c 06 8b c6 99 f7 7d 14 8b 45 0c 8a 04 02 30 01 46 3b 75 10 7e e6 } //02 00 
		$a_01_1 = {53 75 72 72 65 6e 64 48 6f 6d 65 } //02 00  SurrendHome
		$a_01_2 = {41 76 74 2d 4e 65 74 } //02 00  Avt-Net
		$a_01_3 = {58 32 74 72 5a 7a 45 6b 4a 47 4a 61 61 47 68 57 58 46 70 70 4a 57 39 65 57 47 63 6c 5a 56 70 72 4d 53 34 75 39 77 3d 3d } //01 00  X2trZzEkJGJaaGhWXFppJW9eWGclZVprMS4u9w==
		$a_01_4 = {25 73 5c 33 36 30 72 70 76 2e 65 78 65 } //01 00  %s\360rpv.exe
		$a_01_5 = {73 76 63 6e 65 74 33 32 2e 64 6c 6c } //00 00  svcnet32.dll
	condition:
		any of ($a_*)
 
}