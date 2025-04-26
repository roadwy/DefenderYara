
rule PWS_Win32_QQpass_BE{
	meta:
		description = "PWS:Win32/QQpass.BE,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {51 51 2e 65 78 65 2a 54 4d 53 68 65 6c 6c 2e 65 78 65 2a 54 49 4d 50 6c 61 74 66 6f 72 6d 2e 65 78 65 2a 52 74 78 63 2e 65 78 65 2a 58 64 69 63 74 2e 65 78 65 2a 63 6c 65 61 72 68 69 73 74 6f 72 79 2e 65 78 65 2a 47 61 6d 65 47 75 61 72 64 2e 64 65 73 } //1 QQ.exe*TMShell.exe*TIMPlatform.exe*Rtxc.exe*Xdict.exe*clearhistory.exe*GameGuard.des
		$a_01_1 = {25 78 5f 7b 36 30 35 32 37 32 43 39 2d 42 41 45 34 2d 34 38 32 36 2d 39 31 38 31 2d 38 43 39 30 41 38 39 46 46 30 33 41 7d } //1 %x_{605272C9-BAE4-4826-9181-8C90A89FF03A}
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}