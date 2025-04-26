
rule Trojan_Win32_QQProtect_A_ibt{
	meta:
		description = "Trojan:Win32/QQProtect.A!ibt,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {75 72 6c 28 27 72 65 73 3a 2f 2f 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 2f 70 69 63 74 75 72 65 2e 61 35 61 27 29 } //1 url('res://kernel32.dll/picture.a5a')
		$a_01_1 = {6f 6e 6b 65 79 64 6f 77 6e 3d 27 69 66 28 77 69 6e 64 6f 77 2e 65 76 65 6e 74 2e 6b 65 79 43 6f 64 65 3d 3d 32 37 29 } //1 onkeydown='if(window.event.keyCode==27)
		$a_01_2 = {2a 59 69 59 75 59 61 6e 57 6f 43 68 69 4c 65 2a 2e 68 74 6d } //1 *YiYuYanWoChiLe*.htm
		$a_01_3 = {43 3a 5c 54 45 4d 50 5c 53 79 73 71 65 6d 6b 74 6d 73 76 2e 65 78 65 } //1 C:\TEMP\Sysqemktmsv.exe
		$a_01_4 = {51 51 50 72 6f 74 65 63 74 2e 65 78 65 } //1 QQProtect.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}