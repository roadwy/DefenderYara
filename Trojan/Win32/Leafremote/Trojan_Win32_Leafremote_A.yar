
rule Trojan_Win32_Leafremote_A{
	meta:
		description = "Trojan:Win32/Leafremote.A,SIGNATURE_TYPE_PEHSTR,3c 00 3c 00 06 00 00 "
		
	strings :
		$a_01_0 = {6e 65 74 20 75 73 65 72 20 67 75 65 73 74 20 31 32 33 34 71 77 65 52 52 } //10 net user guest 1234qweRR
		$a_01_1 = {2c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 2c 47 75 65 73 74 2c 76 6d 77 61 72 65 } //10 ,Administrator,Guest,vmware
		$a_01_2 = {65 63 68 6f 20 73 69 67 6e 61 74 75 72 65 3d 24 43 48 49 43 41 47 4f 24 } //10 echo signature=$CHICAGO$
		$a_01_3 = {57 4d 49 43 20 55 53 45 52 41 43 43 4f 55 4e 54 20 57 48 45 52 45 20 22 4e 61 6d 65 20 3d 20 27 67 75 65 73 74 27 } //10 WMIC USERACCOUNT WHERE "Name = 'guest'
		$a_01_4 = {53 45 43 45 44 49 54 20 2f 43 4f 4e 46 49 47 55 52 45 20 2f 43 46 47 } //10 SECEDIT /CONFIGURE /CFG
		$a_01_5 = {66 00 61 00 69 00 6c 00 65 00 64 00 20 00 77 00 2f 00 65 00 72 00 72 00 20 00 30 00 78 00 25 00 30 00 38 00 6c 00 78 00 } //10 failed w/err 0x%08lx
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10) >=60
 
}