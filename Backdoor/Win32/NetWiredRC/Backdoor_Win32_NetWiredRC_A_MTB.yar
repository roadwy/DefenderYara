
rule Backdoor_Win32_NetWiredRC_A_MTB{
	meta:
		description = "Backdoor:Win32/NetWiredRC.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {52 65 67 53 76 63 73 2e 65 78 65 } //1 RegSvcs.exe
		$a_81_1 = {5c 61 73 67 72 65 67 2e 65 78 65 } //1 \asgreg.exe
		$a_81_2 = {2a 2f 2a 47 2a 2f 2a 65 2a 2f 2a 74 2a 2f 2a 4d 2a 2f 2a 65 2a 2f 2a 74 2a 2f 2a 68 2a 2f 2a 6f 2a 2f 2a 64 } //1 */*G*/*e*/*t*/*M*/*e*/*t*/*h*/*o*/*d
		$a_81_3 = {32 31 35 34 44 38 32 41 34 46 30 33 34 30 41 41 44 46 30 41 42 35 44 37 36 44 36 46 38 46 30 46 32 45 36 43 45 33 32 39 37 35 31 37 43 33 45 39 45 35 34 41 45 45 36 46 35 39 46 30 } //1 2154D82A4F0340AADF0AB5D76D6F8F0F2E6CE3297517C3E9E54AEE6F59F0
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}