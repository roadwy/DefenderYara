
rule Trojan_Win64_XMRig_WQ_MTB{
	meta:
		description = "Trojan:Win64/XMRig.WQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {4f 6d 4e 6f 6d 2e 65 78 65 } //1 OmNom.exe
		$a_81_1 = {41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 } //1 Add-MpPreference -ExclusionPath
		$a_81_2 = {44 65 66 65 6e 64 65 72 2d 41 75 73 6e 61 68 6d 65 6e } //1 Defender-Ausnahmen
		$a_81_3 = {75 62 72 69 6e 2e 70 64 62 } //1 ubrin.pdb
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}