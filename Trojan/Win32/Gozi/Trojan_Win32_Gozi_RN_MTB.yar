
rule Trojan_Win32_Gozi_RN_MTB{
	meta:
		description = "Trojan:Win32/Gozi.RN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6c 69 66 74 5c 46 6f 75 6e 64 5c 4f 63 65 61 6e 5c 68 6f 6c 65 5c 48 61 74 5c 43 61 6d 65 5c 48 6f 6c 65 67 72 6f 75 70 2e 70 64 62 } //1 lift\Found\Ocean\hole\Hat\Came\Holegroup.pdb
		$a_01_1 = {70 72 65 73 73 6d 6f 6d 65 6e 74 20 62 69 74 20 64 65 74 65 72 6d 69 6e 65 } //1 pressmoment bit determine
		$a_01_2 = {33 63 72 6f 77 64 20 6c 6f 67 20 6e 6f 6f 6e 20 63 61 6e } //1 3crowd log noon can
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}