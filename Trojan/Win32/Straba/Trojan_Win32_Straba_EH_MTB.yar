
rule Trojan_Win32_Straba_EH_MTB{
	meta:
		description = "Trojan:Win32/Straba.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 20 eb 0a a1 ?? ?? ?? ?? 83 c0 20 ff d0 8d 05 ?? ?? ?? ?? 89 18 89 f0 01 05 ?? ?? ?? ?? 89 ea 89 15 ?? ?? ?? ?? 01 3d ?? ?? ?? ?? eb d6 c3 89 45 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Straba_EH_MTB_2{
	meta:
		description = "Trojan:Win32/Straba.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {67 00 72 00 65 00 65 00 6e 00 41 00 6d 00 6f 00 76 00 65 00 74 00 68 00 4f 00 75 00 72 00 68 00 65 00 41 00 66 00 6f 00 72 00 6d 00 67 00 72 00 61 00 73 00 73 00 } //1 greenAmovethOurheAformgrass
		$a_01_1 = {38 00 4d 00 6f 00 76 00 69 00 6e 00 67 00 63 00 72 00 65 00 65 00 70 00 65 00 74 00 68 00 6d 00 61 00 79 00 45 00 } //1 8MovingcreepethmayE
		$a_01_2 = {30 00 74 00 6d 00 61 00 79 00 4b 00 73 00 61 00 79 00 69 00 6e 00 67 00 } //1 0tmayKsaying
		$a_01_3 = {6d 00 61 00 6c 00 65 00 74 00 68 00 65 00 69 00 72 00 77 00 65 00 71 00 } //1 maletheirweq
		$a_01_4 = {71 00 74 00 72 00 65 00 65 00 47 00 53 00 69 00 77 00 61 00 73 00 } //1 qtreeGSiwas
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Straba_EH_MTB_3{
	meta:
		description = "Trojan:Win32/Straba.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {46 00 66 00 69 00 6c 00 6c 00 63 00 62 00 65 00 68 00 6f 00 6c 00 64 00 45 00 79 00 6f 00 75 00 2e 00 72 00 65 00 69 00 74 00 73 00 65 00 6c 00 66 00 6a 00 } //1 FfillcbeholdEyou.reitselfj
		$a_01_1 = {70 00 6c 00 61 00 63 00 65 00 47 00 6d 00 65 00 61 00 74 00 57 00 56 00 54 00 } //1 placeGmeatWVT
		$a_01_2 = {67 00 41 00 6c 00 69 00 66 00 65 00 56 00 76 00 66 00 61 00 63 00 65 00 63 00 72 00 65 00 65 00 70 00 69 00 6e 00 67 00 55 00 } //1 gAlifeVvfacecreepingU
		$a_01_3 = {71 00 64 00 72 00 79 00 6d 00 65 00 61 00 74 00 67 00 72 00 65 00 65 00 6e 00 6e 00 74 00 73 00 65 00 61 00 73 00 6f 00 6e 00 73 00 } //1 qdrymeatgreenntseasons
		$a_01_4 = {4c 00 69 00 67 00 68 00 74 00 62 00 6c 00 65 00 73 00 73 00 65 00 64 00 68 00 69 00 73 00 32 00 62 00 } //1 Lightblessedhis2b
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}