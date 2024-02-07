
rule Backdoor_Win32_Wannaren_D_MTB{
	meta:
		description = "Backdoor:Win32/Wannaren.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {42 61 63 6b 64 6f 6f 72 20 72 65 74 75 72 6e 65 64 20 63 6f 64 65 3a } //01 00  Backdoor returned code:
		$a_81_1 = {2d 2d 54 61 72 67 65 74 50 6f 72 74 20 34 34 35 20 2d 2d 50 72 6f 74 6f 63 6f 6c 20 53 4d 42 20 2d 2d 41 72 63 68 69 74 65 63 74 75 72 65 20 78 36 34 20 2d 2d 46 75 6e 63 74 69 6f 6e 20 52 75 6e 44 4c 4c 20 2d 2d 44 6c 6c 50 61 79 6c 6f 61 64 } //01 00  --TargetPort 445 --Protocol SMB --Architecture x64 --Function RunDLL --DllPayload
		$a_81_2 = {45 74 65 72 6e 61 6c 62 6c 75 65 } //01 00  Eternalblue
		$a_81_3 = {44 6f 75 62 6c 65 70 75 6c 73 61 72 } //00 00  Doublepulsar
	condition:
		any of ($a_*)
 
}