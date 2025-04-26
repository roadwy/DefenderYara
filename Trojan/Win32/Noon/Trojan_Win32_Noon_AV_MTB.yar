
rule Trojan_Win32_Noon_AV_MTB{
	meta:
		description = "Trojan:Win32/Noon.AV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_81_0 = {77 73 70 79 67 7a 6d 68 2e 70 64 62 } //3 wspygzmh.pdb
		$a_81_1 = {75 72 6e 73 70 66 70 67 } //3 urnspfpg
		$a_81_2 = {44 69 73 61 73 73 6f 63 69 61 74 65 43 6f 6c 6f 72 50 72 6f 66 69 6c 65 46 72 6f 6d 44 65 76 69 63 65 57 } //3 DisassociateColorProfileFromDeviceW
		$a_81_3 = {57 4e 65 74 47 65 74 52 65 73 6f 75 72 63 65 49 6e 66 6f 72 6d 61 74 69 6f 6e 57 } //3 WNetGetResourceInformationW
		$a_81_4 = {76 71 6b 6c 71 6a 61 2e 64 6c 6c } //3 vqklqja.dll
		$a_81_5 = {5c 73 6f 62 72 69 65 74 79 5c 64 72 61 67 5c 72 65 6c 61 74 69 6e 67 2e 6d 64 62 } //3 \sobriety\drag\relating.mdb
		$a_81_6 = {6d 69 72 61 63 75 6c 6f 75 73 2e 64 6c 6c } //3 miraculous.dll
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3) >=21
 
}