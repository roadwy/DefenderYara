
rule PWS_Win32_QQpass_EZ{
	meta:
		description = "PWS:Win32/QQpass.EZ,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 6d 61 69 6c 2e 61 73 70 } //1 /mail.asp
		$a_01_1 = {26 71 71 70 61 73 73 77 6f 72 64 3d } //1 &qqpassword=
		$a_01_2 = {3f 71 71 6e 75 6d 62 65 72 3d } //1 ?qqnumber=
		$a_01_3 = {42 69 6e 5c 51 51 2e 65 78 65 } //1 Bin\QQ.exe
		$a_01_4 = {5c 41 6c 6c 20 55 73 65 72 73 5c 51 51 5c 52 65 67 69 73 74 72 79 2e 64 62 } //1 \All Users\QQ\Registry.db
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}