
rule Trojan_Win32_AutoitInject_AN_MSR{
	meta:
		description = "Trojan:Win32/AutoitInject.AN!MSR,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6a 00 6f 00 6b 00 4d 00 2e 00 63 00 6f 00 6d 00 } //1 jokM.com
		$a_01_1 = {72 00 6c 00 55 00 56 00 5a 00 2e 00 65 00 78 00 65 00 } //1 rlUVZ.exe
		$a_01_2 = {67 00 52 00 47 00 74 00 2e 00 65 00 78 00 65 00 } //1 gRGt.exe
		$a_01_3 = {55 00 6d 00 66 00 4b 00 62 00 2e 00 65 00 78 00 65 00 } //1 UmfKb.exe
		$a_01_4 = {6a 00 66 00 69 00 70 00 6f 00 6c 00 6b 00 6f 00 2e 00 65 00 78 00 65 00 } //1 jfipolko.exe
		$a_01_5 = {52 00 65 00 61 00 6c 00 6c 00 79 00 20 00 63 00 61 00 6e 00 63 00 65 00 6c 00 20 00 74 00 68 00 65 00 20 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 } //1 Really cancel the installation
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}