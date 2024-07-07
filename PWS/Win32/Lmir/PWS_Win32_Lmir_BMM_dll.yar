
rule PWS_Win32_Lmir_BMM_dll{
	meta:
		description = "PWS:Win32/Lmir.BMM!dll,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //1 \drivers\etc\hosts
		$a_01_1 = {6d 69 72 31 2e 64 61 74 } //1 mir1.dat
		$a_01_2 = {6d 5f 4c 6f 67 69 6e 41 64 64 72 3a } //1 m_LoginAddr:
		$a_01_3 = {6d 5f 53 65 72 76 65 72 41 64 64 72 3a } //1 m_ServerAddr:
		$a_01_4 = {6d 5f 4d 42 50 59 43 6f 6e 73 74 41 64 64 72 3a } //1 m_MBPYConstAddr:
		$a_01_5 = {2f 43 51 53 65 72 76 65 72 2f 72 65 63 76 4d 61 69 6c 2e 61 73 70 3f 55 73 65 72 50 57 44 3d } //1 /CQServer/recvMail.asp?UserPWD=
		$a_01_6 = {73 76 63 68 6f 73 74 2e 48 } //1 svchost.H
		$a_01_7 = {61 6e 74 69 76 69 72 75 73 2e 65 78 7c } //1 antivirus.ex|
		$a_01_8 = {6d 73 6d 70 73 76 63 2e } //1 msmpsvc.
		$a_01_9 = {66 73 61 76 2e 65 78 65 } //1 fsav.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}