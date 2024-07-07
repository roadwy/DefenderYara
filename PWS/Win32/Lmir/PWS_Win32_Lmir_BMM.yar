
rule PWS_Win32_Lmir_BMM{
	meta:
		description = "PWS:Win32/Lmir.BMM,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //1 \drivers\etc\hosts
		$a_01_1 = {6d 69 72 31 2e 64 61 74 } //1 mir1.dat
		$a_01_2 = {4d 69 72 41 5a 42 43 6f 6e 73 74 41 64 64 72 3a } //1 MirAZBConstAddr:
		$a_01_3 = {6d 5f 53 65 72 76 65 72 41 64 64 72 3a } //1 m_ServerAddr:
		$a_01_4 = {2f 43 51 53 65 72 76 65 72 2f 72 65 63 76 4d 61 69 6c 2e 61 73 70 3f 55 73 65 72 50 57 44 3d } //1 /CQServer/recvMail.asp?UserPWD=
		$a_01_5 = {61 76 70 33 32 2e 65 78 } //1 avp32.ex
		$a_01_6 = {66 73 61 76 2e 65 78 65 } //1 fsav.exe
		$a_01_7 = {6d 73 6d 70 73 76 63 2e } //1 msmpsvc.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}