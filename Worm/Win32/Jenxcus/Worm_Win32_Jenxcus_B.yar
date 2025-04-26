
rule Worm_Win32_Jenxcus_B{
	meta:
		description = "Worm:Win32/Jenxcus.B,SIGNATURE_TYPE_PEHSTR,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 75 6e 63 74 69 6f 6e 20 70 6f 73 74 20 28 63 6d 64 20 2c 70 61 72 61 6d 29 } //1 function post (cmd ,param)
		$a_01_1 = {2e 6f 70 65 6e 20 22 70 6f 73 74 22 2c 22 68 74 74 70 3a 2f 2f 22 20 26 20 68 6f 73 74 20 26 20 22 3a 22 20 26 20 70 6f 72 74 20 26 22 2f 22 20 26 20 63 6d 64 2c 20 66 61 6c 73 65 } //1 .open "post","http://" & host & ":" & port &"/" & cmd, false
		$a_01_2 = {2e 72 65 67 77 72 69 74 65 20 22 48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 73 6f 66 74 77 61 72 65 5c 22 20 26 20 73 70 6c 69 74 20 28 69 6e 73 74 61 6c 6c 6e 61 6d 65 2c 22 2e 22 29 28 30 29 20 20 26 20 22 5c 22 2c 20 20 75 73 62 73 70 72 65 61 64 69 6e 67 2c 20 22 52 45 47 5f 53 5a 22 } //1 .regwrite "HKEY_LOCAL_MACHINE\software\" & split (installname,".")(0)  & "\",  usbspreading, "REG_SZ"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}