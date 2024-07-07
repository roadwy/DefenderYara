
rule Worm_Win32_Autorun_NE{
	meta:
		description = "Worm:Win32/Autorun.NE,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 75 74 6f 72 55 4e 5d 0d 0a 4f 70 65 4e 3d 0d 0a 73 48 65 4c 6c 5c 6f 50 65 4e 5c 43 4f 6d 6d 61 6e 44 3d 52 45 43 59 43 4c 45 52 5c 53 59 53 54 45 4d 2e 2e 5c 52 45 43 59 43 4c 45 52 0d 0a 73 68 65 6c 4c 5c 45 58 70 6c 4f 72 65 5c 43 4f 6d 6d 61 4e 44 3d 52 45 43 59 43 4c 45 52 5c 53 59 53 54 45 4d 2e 2e 5c 52 45 43 59 43 4c 45 52 0d 0a 73 68 65 6c 4c 5c 66 49 6e 44 5c 43 4f 4d 6d 41 6e 44 3d 52 45 43 59 43 4c 45 52 5c 53 59 53 54 45 4d 2e 2e 5c 52 45 43 59 43 4c 45 52 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}