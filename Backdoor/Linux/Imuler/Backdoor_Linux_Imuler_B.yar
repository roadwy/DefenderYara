
rule Backdoor_Linux_Imuler_B{
	meta:
		description = "Backdoor:Linux/Imuler.B,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 74 6d 70 2f 78 6e 74 61 73 6b 7a } //01 00  /tmp/xntaskz
		$a_01_1 = {25 73 3a 25 73 3a 25 75 3a 25 66 3a 25 66 } //01 00  %s:%s:%u:%f:%f
		$a_01_2 = {28 73 65 72 76 65 72 20 6e 61 6d 65 29 20 28 6d 61 63 68 69 6e 65 20 69 64 29 20 28 66 69 6c 65 20 6e 61 6d 65 29 20 28 74 61 73 6b 20 69 64 29 } //01 00  (server name) (machine id) (file name) (task id)
		$a_01_3 = {2f 63 67 69 2d 6d 61 63 2f } //01 00  /cgi-mac/
		$a_01_4 = {2f 75 73 65 72 73 2f 25 73 2f 78 6e 6f 63 7a 31 } //01 00  /users/%s/xnocz1
		$a_01_5 = {2f 75 73 65 72 73 2f 25 73 2f 6c 69 62 72 61 72 79 2f 2e 63 6f 6e 66 62 61 63 6b } //01 00  /users/%s/library/.confback
		$a_03_6 = {c1 e8 10 f7 c2 80 80 00 00 0f 44 d0 90 02 02 8d 41 02 90 02 02 0f 45 c1 00 d2 90 02 02 83 d8 03 90 02 02 2f 63 67 69 90 00 } //00 00 
		$a_00_7 = {5d 04 00 } //00 2b 
	condition:
		any of ($a_*)
 
}