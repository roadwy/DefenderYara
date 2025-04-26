
rule PWS_Win32_Ldpinch_ZH{
	meta:
		description = "PWS:Win32/Ldpinch.ZH,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 71 2e 71 71 2e 63 6f 6d 2f 63 6e 32 2f 66 69 6e 64 70 73 77 } //1 aq.qq.com/cn2/findpsw
		$a_01_1 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 69 70 2e 74 78 74 } //1 c:\windows\system32\ip.txt
		$a_01_2 = {51 51 2e 65 78 65 } //1 QQ.exe
		$a_01_3 = {33 36 35 32 30 36 39 38 38 40 71 71 2e 63 6f 6d } //1 365206988@qq.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}