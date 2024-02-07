
rule Backdoor_Win32_Fakesuit_B{
	meta:
		description = "Backdoor:Win32/Fakesuit.B,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 75 73 65 72 73 5c 6d 7a 5c 64 6f 63 75 6d 65 6e 74 73 5c 76 69 73 75 61 6c 20 73 74 75 64 69 6f 20 32 30 31 33 5c 50 72 6f 6a 65 63 74 73 5c 53 68 65 6c 6c 63 6f 64 65 5c 52 65 6c 65 61 73 65 5c 53 68 65 6c 6c 63 6f 64 65 2e 70 64 62 } //00 00  c:\users\mz\documents\visual studio 2013\Projects\Shellcode\Release\Shellcode.pdb
	condition:
		any of ($a_*)
 
}