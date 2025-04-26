
rule Trojan_Win32_Syndicasec_C{
	meta:
		description = "Trojan:Win32/Syndicasec.C,SIGNATURE_TYPE_PEHSTR_EXT,07 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {70 47 6c 6f 62 61 6c 2d 3e 6e 4f 53 54 79 70 65 3d 3d 36 34 2d 2d 25 73 5c 63 6d 64 2e 65 78 65 20 25 73 } //1 pGlobal->nOSType==64--%s\cmd.exe %s
		$a_01_1 = {5c 43 72 79 70 74 42 61 73 65 2e 64 6c 6c } //1 \CryptBase.dll
		$a_01_2 = {67 75 70 64 61 74 65 2e 65 78 65 } //1 gupdate.exe
		$a_01_3 = {77 75 73 61 2e 65 78 65 } //1 wusa.exe
		$a_01_4 = {68 74 74 70 63 6f 6d 2e 6c 6f 67 } //1 httpcom.log
		$a_01_5 = {25 73 25 73 2e 64 6c 6c 2e 63 61 62 } //1 %s%s.dll.cab
		$a_01_6 = {52 65 6c 65 61 73 65 45 76 69 6c 64 6c 6c } //1 ReleaseEvildll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}