
rule TrojanProxy_Win32_Wonknod_B{
	meta:
		description = "TrojanProxy:Win32/Wonknod.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {3d 25 64 2c c7 45 90 01 01 70 69 64 3d 90 00 } //1
		$a_01_1 = {5c 56 43 20 50 72 6f 6a 65 63 74 5c 42 79 70 61 73 73 55 61 63 5c } //1 \VC Project\BypassUac\
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanProxy_Win32_Wonknod_B_2{
	meta:
		description = "TrojanProxy:Win32/Wonknod.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {6e 61 6d 65 66 90 01 01 45 e4 3d 00 c7 45 90 01 01 63 6f 6e 74 90 00 } //1
		$a_01_1 = {67 65 74 66 69 6c 65 2e 6c 70 3f 6e 61 6d 65 3d 64 62 2e 7a 69 70 26 61 63 74 69 6f 6e 3d 61 72 67 } //1 getfile.lp?name=db.zip&action=arg
		$a_01_2 = {31 6f 6e 5f 6d 6f 6e 69 74 6f 72 54 69 6d 65 72 5f 74 69 6d 65 6f 75 74 28 29 } //1 1on_monitorTimer_timeout()
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanProxy_Win32_Wonknod_B_3{
	meta:
		description = "TrojanProxy:Win32/Wonknod.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 64 31 2e 74 72 69 70 64 65 73 74 69 6e 66 6f 2e 63 6f 6d 2f 78 36 34 2e 7a 69 70 } //1 http://d1.tripdestinfo.com/x64.zip
		$a_01_1 = {68 74 74 70 3a 2f 2f 64 31 2e 74 72 69 70 64 65 73 74 69 6e 66 6f 2e 63 6f 6d 2f 78 33 32 2e 7a 69 70 } //1 http://d1.tripdestinfo.com/x32.zip
		$a_01_2 = {68 74 74 70 3a 2f 2f 64 31 2e 74 72 69 70 64 65 73 74 69 6e 66 6f 2e 63 6f 6d 2f 63 74 33 2e 7a 69 70 } //1 http://d1.tripdestinfo.com/ct3.zip
		$a_03_3 = {78 36 34 2e c7 84 24 90 01 02 00 00 7a 69 70 00 c7 84 24 90 01 02 00 00 78 36 34 2e c7 84 24 90 01 02 00 00 65 78 65 00 c7 84 24 90 01 02 00 00 78 33 32 2e c7 84 24 90 01 02 00 00 7a 69 70 00 c7 84 24 90 01 02 00 00 78 33 32 2e c7 84 24 90 01 02 00 00 65 78 65 00 90 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*2) >=4
 
}