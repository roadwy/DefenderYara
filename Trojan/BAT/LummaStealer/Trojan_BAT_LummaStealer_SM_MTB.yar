
rule Trojan_BAT_LummaStealer_SM_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_81_0 = {43 6f 73 6d 69 63 45 64 67 65 20 54 65 63 68 6e 6f 6c 6f 67 69 65 73 20 54 72 61 64 65 6d 61 72 6b } //2 CosmicEdge Technologies Trademark
		$a_81_1 = {24 65 33 64 32 66 38 61 39 2d 62 37 63 35 2d 34 61 32 33 2d 38 64 31 32 2d 36 35 34 33 32 61 62 63 64 65 39 30 } //2 $e3d2f8a9-b7c5-4a23-8d12-65432abcde90
		$a_81_2 = {50 75 73 68 69 6e 67 20 74 68 65 20 62 6f 75 6e 64 61 72 69 65 73 20 6f 66 20 74 65 63 68 6e 6f 6c 6f 67 79 20 66 6f 72 20 61 20 62 72 69 67 68 74 65 72 20 74 6f 6d 6f 72 72 6f 77 } //2 Pushing the boundaries of technology for a brighter tomorrow
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2) >=6
 
}