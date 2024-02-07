
rule HackTool_Linux_BloodHound_A_MTB{
	meta:
		description = "HackTool:Linux/BloodHound.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 62 6c 6f 6f 64 68 6f 75 6e 64 61 64 2f 61 7a 75 72 65 68 6f 75 6e 64 } //01 00  /bloodhoundad/azurehound
		$a_01_1 = {49 66 56 31 32 4b 38 78 41 4b 41 6e 5a 71 64 58 56 7a 43 5a 2b 54 4f 6a 62 6f 5a 32 6b 65 4c 67 38 31 65 58 66 57 33 4f 2b 6f 59 3d } //01 00  IfV12K8xAKAnZqdXVzCZ+TOjboZ2keLg81eXfW3O+oY=
		$a_01_2 = {66 59 35 42 4f 53 70 79 5a 43 71 52 6f 35 4f 68 43 75 43 2b 58 4e 2b 72 2f 62 42 43 6d 65 75 75 4a 74 6a 7a 2b 62 43 4e 49 66 38 3d } //01 00  fY5BOSpyZCqRo5OhCuC+XN+r/bBCmeuuJtjz+bCNIf8=
		$a_01_3 = {74 6a 45 4e 46 36 4d 66 5a 41 67 38 65 34 5a 6d 5a 54 65 57 61 57 69 54 32 76 58 74 73 6f 4f 36 2b 69 75 4f 6a 46 68 45 43 77 4d 3d } //01 00  tjENF6MfZAg8e4ZmZTeWaWiT2vXtsoO6+iuOjFhECwM=
		$a_01_4 = {30 41 6e 6c 7a 6a 70 69 34 76 45 61 73 54 65 4e 46 6e 32 6d 4c 4a 67 54 53 77 74 30 2b 36 73 66 73 69 54 47 38 71 63 57 47 78 34 3d } //01 00  0Anlzjpi4vEasTeNFn2mLJgTSwt0+6sfsiTG8qcWGx4=
		$a_01_5 = {44 38 78 67 77 45 43 59 37 43 59 76 78 2b 59 32 6e 34 73 42 7a 39 33 4a 6e 39 4a 52 76 78 64 69 79 79 6f 38 43 54 66 75 4b 61 59 3d } //00 00  D8xgwECY7CYvx+Y2n4sBz93Jn9JRvxdiyyo8CTfuKaY=
	condition:
		any of ($a_*)
 
}