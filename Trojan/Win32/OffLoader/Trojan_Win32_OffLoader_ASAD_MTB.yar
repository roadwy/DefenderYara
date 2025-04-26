
rule Trojan_Win32_OffLoader_ASAD_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.ASAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 "
		
	strings :
		$a_01_0 = {62 72 61 73 73 66 6f 72 63 65 2e 73 69 74 65 2f 70 6c 6f 73 73 2e 70 68 70 3f 61 3d } //2 brassforce.site/ploss.php?a=
		$a_01_1 = {73 74 6f 2e 66 61 72 6d 73 63 65 6e 65 2e 77 65 62 73 69 74 65 2f 74 72 61 63 6b } //2 sto.farmscene.website/track
		$a_03_2 = {76 63 72 65 64 69 73 74 5f 78 36 34 2e 65 78 65 [0-10] 5c 69 6e 65 74 63 2e 64 6c 6c } //2
		$a_01_3 = {77 65 61 6b 73 65 63 75 72 69 74 79 } //2 weaksecurity
		$a_01_4 = {56 45 52 59 53 49 4c 45 4e 54 20 2f 50 41 53 53 57 4f 52 44 3d 4e 74 49 52 56 55 70 4d 4b 39 5a 44 33 30 4e 66 39 38 32 32 30 } //1 VERYSILENT /PASSWORD=NtIRVUpMK9ZD30Nf98220
		$a_01_5 = {56 45 52 59 53 49 4c 45 4e 54 20 2f 53 55 50 50 52 45 53 53 4d 53 47 42 4f 58 45 53 } //1 VERYSILENT /SUPPRESSMSGBOXES
		$a_01_6 = {6f 6e 6c 79 2f 70 70 62 61 } //1 only/ppba
		$a_01_7 = {71 6e 20 43 41 4d 50 41 49 47 4e 3d } //1 qn CAMPAIGN=
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=10
 
}