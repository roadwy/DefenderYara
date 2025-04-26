
rule Trojan_Win32_CryptInject_SD_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 11 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 e8 01 a3 [0-08] 8b 15 ?? ?? ?? ?? 8b c0 83 c2 01 ?? ?? a1 ?? ?? ?? ?? 8b c0 8b ca 8b c0 a3 ?? ?? ?? ?? 8b c0 31 0d ?? ?? ?? ?? 8b c0 a1 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 11 5d c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_CryptInject_SD_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.SD!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 50 72 6f 67 72 61 6d 6d 65 5c 41 75 74 6f 73 74 61 72 74 5c } //1 \Programme\Autostart\
		$a_01_1 = {5c 65 78 63 2e 65 78 65 } //1 \exc.exe
		$a_01_2 = {57 69 6e 33 32 2e 63 72 41 63 6b 65 72 2e 41 } //1 Win32.crAcker.A
		$a_01_3 = {79 6f 75 70 6f 72 6e 2e 63 6f 6d } //1 youporn.com
		$a_01_4 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}