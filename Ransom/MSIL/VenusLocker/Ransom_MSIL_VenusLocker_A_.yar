
rule Ransom_MSIL_VenusLocker_A_{
	meta:
		description = "Ransom:MSIL/VenusLocker.A!!VenusLocker.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_80_0 = {2e 56 65 6e 75 73 66 } //.Venusf  1
		$a_80_1 = {2e 56 65 6e 75 73 70 } //.Venusp  1
		$a_80_2 = {56 65 6e 75 73 4c 6f 63 6b 65 72 20 54 65 61 6d } //VenusLocker Team  1
		$a_80_3 = {4c 6f 63 6b 65 72 50 69 63 42 6f 78 } //LockerPicBox  1
		$a_80_4 = {59 6f 75 72 20 61 72 65 20 68 61 63 6b 65 64 } //Your are hacked  1
		$a_80_5 = {5c 56 65 6e 75 73 4c 6f 63 6b 65 72 56 32 5c 56 65 6e 75 73 4c 6f 63 6b 65 72 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 56 65 6e 75 73 4c 6f 63 6b 65 72 2e 70 64 62 00 } //\VenusLockerV2\VenusLocker\obj\Release\VenusLocker.pdb  1
		$a_80_6 = {56 65 6e 75 73 4c 6f 63 6b 65 72 2e 65 78 65 00 } //VenusLocker.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=5
 
}