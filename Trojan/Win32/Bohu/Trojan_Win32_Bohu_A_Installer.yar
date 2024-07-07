
rule Trojan_Win32_Bohu_A_Installer{
	meta:
		description = "Trojan:Win32/Bohu.A!Installer,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {25 25 5c 6e 65 74 68 6f 6d 65 33 32 2e 64 6c 6c 20 52 75 6e 64 6c 6c 49 6e 73 74 61 6c 6c 20 4e 65 74 48 6f 6d 65 49 44 45 } //1 %%\nethome32.dll RundllInstall NetHomeIDE
		$a_01_1 = {25 25 5c 6e 65 74 70 6c 61 79 6f 6e 65 5c 4d 79 49 45 44 61 74 61 } //1 %%\netplayone\MyIEData
		$a_01_2 = {64 6e 73 20 36 31 2e 31 35 38 2e 31 36 30 2e 31 39 37 2c 36 31 2e 31 35 38 2e 31 36 30 2e 32 30 36 } //1 dns 61.158.160.197,61.158.160.206
		$a_01_3 = {6d 73 66 73 67 2e 65 78 65 20 6d 64 35 20 2d 73 20 73 70 61 73 73 2e 64 6c 6c 20 2d 64 20 73 70 61 73 73 2e 64 6c 6c } //1 msfsg.exe md5 -s spass.dll -d spass.dll
		$a_01_4 = {5c 62 61 69 64 75 5c 64 73 65 74 75 70 2e 65 78 65 20 69 6e 73 74 61 6c 6c } //1 \baidu\dsetup.exe install
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}