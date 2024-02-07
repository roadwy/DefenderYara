
rule Backdoor_Win32_Blackhole_L{
	meta:
		description = "Backdoor:Win32/Blackhole.L,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {31 33 38 73 6f 66 74 2e 63 6f 6d 2f 62 6c 61 63 6b 68 6f 6c 65 2f 76 65 72 69 66 79 2e 61 73 70 3f 6d 64 35 3d } //01 00  138soft.com/blackhole/verify.asp?md5=
		$a_00_1 = {3a 28 52 61 6d 20 44 69 73 6b 29 } //01 00  :(Ram Disk)
		$a_00_2 = {42 72 63 53 65 72 76 65 72 32 2e 45 78 65 } //0a 00  BrcServer2.Exe
		$a_02_3 = {0f 84 8e 00 00 00 b8 90 01 04 ba 1c 00 00 00 e8 90 01 04 c7 05 90 01 04 10 01 00 00 c7 05 90 01 04 02 00 00 00 c7 05 90 01 04 03 00 00 00 c7 05 90 01 04 e8 03 00 00 68 90 01 04 a1 90 01 04 50 e8 90 01 04 c6 05 90 01 04 00 c6 05 90 01 04 00 c7 05 90 01 04 04 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}