
rule Worm_Win32_Radoom_A{
	meta:
		description = "Worm:Win32/Radoom.A,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 72 6f 74 65 63 74 6f 72 2e 65 78 65 00 73 76 63 68 6f 73 74 2e 65 78 65 } //10
		$a_02_1 = {5b 61 75 74 6f 72 75 6e 5d [0-04] 73 68 65 6c 6c 65 78 65 63 75 74 65 3d 25 73 } //10
		$a_00_2 = {73 65 6e 64 20 24 6e 69 63 6b 20 43 48 41 4e 4e 45 4c 2d 52 55 4c 45 53 } //5 send $nick CHANNEL-RULES
		$a_00_3 = {44 6f 6f 6d 73 64 61 79 20 48 61 73 20 43 6f 6d 65 } //1 Doomsday Has Come
		$a_00_4 = {59 4f 55 20 41 52 45 20 69 4e 46 45 43 54 45 44 20 42 59 20 52 41 56 4f 5f 35 30 30 32 } //1 YOU ARE iNFECTED BY RAVO_5002
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*5+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=26
 
}