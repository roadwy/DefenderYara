
rule PWS_Win32_QQThief_I{
	meta:
		description = "PWS:Win32/QQThief.I,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {25 73 5c 7e 40 66 61 74 48 6a 25 64 2e 65 78 65 } //1 %s\~@fatHj%d.exe
		$a_01_1 = {25 73 25 73 00 00 00 00 5c 65 78 70 6c 00 00 00 6f 72 65 72 2e 65 78 65 } //1
		$a_01_2 = {46 41 54 33 32 2e 64 6c 6c 00 44 65 61 6c 41 00 44 65 61 6c 42 } //1
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 54 65 6e 63 65 6e 74 5c 51 51 5c } //1 SOFTWARE\Tencent\QQ\
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}