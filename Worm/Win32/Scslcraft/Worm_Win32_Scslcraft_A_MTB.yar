
rule Worm_Win32_Scslcraft_A_MTB{
	meta:
		description = "Worm:Win32/Scslcraft.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {73 63 61 6e 73 6c 61 6d 20 5b 2d 72 3c 6e 3e 5d 20 3c 68 6f 73 74 31 3e 20 3c 68 6f 73 74 32 2d 68 6f 73 74 33 3e } //1 scanslam [-r<n>] <host1> <host2-host3>
		$a_81_1 = {65 72 72 3a 20 73 65 6e 64 74 6f 28 25 64 2e 25 64 2e 25 64 2e 25 64 3a 25 64 29 20 25 64 } //1 err: sendto(%d.%d.%d.%d:%d) %d
		$a_81_2 = {3d 20 63 72 61 66 74 65 64 20 70 61 63 6b 65 74 20 69 6e 20 3c 66 69 6c 65 3e } //1 = crafted packet in <file>
		$a_81_3 = {3d 20 44 6f 53 20 72 61 74 68 65 72 20 74 68 61 6e 20 73 63 61 6e } //1 = DoS rather than scan
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}