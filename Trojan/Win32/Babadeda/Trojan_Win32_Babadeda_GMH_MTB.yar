
rule Trojan_Win32_Babadeda_GMH_MTB{
	meta:
		description = "Trojan:Win32/Babadeda.GMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {5c 45 6e 76 5f 44 58 38 5c 4e 6f 73 74 61 6c 67 69 61 2e 65 78 65 } //\Env_DX8\Nostalgia.exe  1
		$a_01_1 = {58 59 6b 4c 56 58 53 46 } //1 XYkLVXSF
		$a_01_2 = {58 54 40 46 68 6d 61 63 42 } //1 XT@FhmacB
		$a_01_3 = {61 66 31 36 7a 64 36 } //1 af16zd6
		$a_80_4 = {5c 45 6e 76 5f 44 58 39 5c 43 6f 6e 71 75 65 72 2e 65 78 65 } //\Env_DX9\Conquer.exe  1
		$a_80_5 = {50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 41 75 74 6f 50 61 74 63 68 2e 65 78 65 } //Program Files\AutoPatch.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}