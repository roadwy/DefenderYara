
rule PWS_Win32_QQThief_E{
	meta:
		description = "PWS:Win32/QQThief.E,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {81 ec 2c 01 00 00 56 68 60 ea 00 00 ff 15 90 01 04 6a 00 6a 02 e8 90 01 02 00 00 8d 8d d4 fe ff ff 89 45 fc 51 50 c7 85 d4 fe ff ff 28 01 00 00 e8 90 00 } //4
		$a_01_1 = {5c 69 6e 6a 65 63 74 6d 73 67 2e 65 78 65 } //1 \injectmsg.exe
		$a_01_2 = {5b 49 4e 46 4f 5d 53 45 4e 44 3a } //1 [INFO]SEND:
		$a_01_3 = {5c 73 79 73 61 75 74 6f 72 75 6e 2e 69 6e 66 } //1 \sysautorun.inf
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}