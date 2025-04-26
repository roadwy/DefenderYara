
rule Trojan_Win32_Qhost_EJ{
	meta:
		description = "Trojan:Win32/Qhost.EJ,SIGNATURE_TYPE_PEHSTR,06 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {62 69 6e 61 72 79 3e 3e 25 77 69 6e 64 69 72 25 2f 53 59 53 } //1 binary>>%windir%/SYS
		$a_01_1 = {67 65 74 20 73 79 73 74 65 6d 5f 72 65 6d 2e 65 78 65 3e 3e 25 77 69 6e 64 69 72 25 2f 53 59 53 } //1 get system_rem.exe>>%windir%/SYS
		$a_01_2 = {40 66 74 70 20 2d 76 69 73 3a 25 77 69 6e 64 69 72 25 2f 53 59 53 } //1 @ftp -vis:%windir%/SYS
		$a_01_3 = {40 63 6f 70 79 20 70 2e 74 78 74 20 22 25 77 69 6e 64 69 72 25 2f 73 79 73 74 65 6d 33 32 2f 64 72 69 76 65 72 73 2f 65 74 63 2f 68 6f 73 74 73 22 20 2f 59 } //1 @copy p.txt "%windir%/system32/drivers/etc/hosts" /Y
		$a_01_4 = {49 46 20 4e 4f 54 20 45 58 49 53 54 20 22 25 77 69 6e 64 69 72 25 2f 66 61 63 65 2e 44 4c 4c 22 20 47 4f 54 4f } //1 IF NOT EXIST "%windir%/face.DLL" GOTO
		$a_01_5 = {63 6f 70 79 20 73 79 73 74 65 6d 5f 72 65 6d 2e 65 78 65 20 22 25 77 69 6e 64 69 72 25 22 20 2f 59 20 2f 42 } //1 copy system_rem.exe "%windir%" /Y /B
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}