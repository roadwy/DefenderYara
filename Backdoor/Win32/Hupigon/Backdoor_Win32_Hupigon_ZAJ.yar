
rule Backdoor_Win32_Hupigon_ZAJ{
	meta:
		description = "Backdoor:Win32/Hupigon.ZAJ,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_00_0 = {5c b3 cc d0 f2 5c c6 f4 b6 af 5c } //2
		$a_01_1 = {00 4d 79 4c 69 76 65 00 } //2 䴀䱹癩e
		$a_00_2 = {5c 74 65 73 6c 6f 72 74 6e 6f 63 74 6e 65 72 72 75 63 5c } //2 \teslortnoctnerruc\
		$a_00_3 = {5c 73 65 72 76 65 72 2e 65 78 65 } //1 \server.exe
		$a_00_4 = {33 36 30 74 72 61 79 2e 65 78 65 } //1 360tray.exe
		$a_00_5 = {33 36 25 78 73 76 63 } //1 36%xsvc
	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=7
 
}