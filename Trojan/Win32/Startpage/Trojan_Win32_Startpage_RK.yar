
rule Trojan_Win32_Startpage_RK{
	meta:
		description = "Trojan:Win32/Startpage.RK,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 57 69 6e 33 32 47 61 6d 65 73 5c 5c 75 72 6c 2e 64 6c 6c } //1 \Win32Games\\url.dll
		$a_01_1 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 2f 63 20 73 79 73 75 72 6c 2e 64 6c 6c } //1 rundll32.exe /c sysurl.dll
		$a_01_2 = {72 65 67 73 76 72 33 32 2e 65 78 65 20 2f 63 20 73 79 73 70 6f 77 65 72 75 65 73 2e 64 6c 6c } //1 regsvr32.exe /c syspowerues.dll
		$a_01_3 = {68 25 74 25 74 25 70 25 3a 25 2f 25 2f 25 77 25 77 25 77 2e 36 64 75 64 75 2e 25 63 25 6f 25 6d 25 2f } //1 h%t%t%p%:%/%/%w%w%w.6dudu.%c%o%m%/
		$a_01_4 = {55 52 4c 2e 64 6c 6c 00 64 6f 73 65 74 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2) >=4
 
}