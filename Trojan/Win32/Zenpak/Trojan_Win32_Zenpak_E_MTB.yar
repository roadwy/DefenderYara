
rule Trojan_Win32_Zenpak_E_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 e4 8b 75 c4 8a 0c 32 32 0c 1f 8b 5d e0 88 0c 33 c7 05 90 01 04 37 22 00 00 81 c6 01 00 00 00 8b 55 f0 39 d6 89 75 c8 0f 84 f3 fe ff ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zenpak_E_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {55 67 42 7b 7a 43 58 48 79 } //1 UgB{zCXHy
		$a_01_1 = {46 30 31 4f 77 47 65 3e 40 } //1 F01OwGe>@
		$a_01_2 = {37 6b 4c 67 72 65 61 74 54 66 72 75 69 74 66 61 63 65 2e 6c 69 66 65 66 72 6f 6d } //1 7kLgreatTfruitface.lifefrom
		$a_01_3 = {25 00 4d 00 72 00 52 00 3c 00 4c 00 55 00 57 00 6e 00 32 00 47 00 75 00 66 00 } //1 %MrR<LUWn2Guf
		$a_01_4 = {61 46 50 35 24 33 2b 72 23 55 39 52 37 } //1 aFP5$3+r#U9R7
		$a_01_5 = {5c 54 4d 54 6e 38 5c 37 6c 72 73 58 53 47 5c 51 64 2e 70 64 62 } //1 \TMTn8\7lrsXSG\Qd.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}