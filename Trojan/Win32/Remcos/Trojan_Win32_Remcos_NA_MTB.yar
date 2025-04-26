
rule Trojan_Win32_Remcos_NA_MTB{
	meta:
		description = "Trojan:Win32/Remcos.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_03_0 = {40 41 46 43 83 c4 04 5e 56 81 f6 ?? ?? ?? ?? 5e 53 57 83 c4 } //10
		$a_81_1 = {6a 65 6e 6b 69 6e 73 2d 77 6f 72 6b 73 70 61 63 65 5c 77 6f 72 6b 73 70 61 63 65 5c 63 6c 69 65 6e 74 2d 62 75 69 6c 64 65 72 2d 70 72 6f 64 75 63 74 5c 42 75 69 6c 64 5c 57 69 6e 33 32 5c 52 65 6c 65 61 73 65 5c 75 74 6f 72 72 65 6e 74 2e 70 64 62 } //5 jenkins-workspace\workspace\client-builder-product\Build\Win32\Release\utorrent.pdb
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*5) >=15
 
}