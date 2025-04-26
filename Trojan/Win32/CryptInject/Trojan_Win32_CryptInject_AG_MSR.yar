
rule Trojan_Win32_CryptInject_AG_MSR{
	meta:
		description = "Trojan:Win32/CryptInject.AG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 74 61 72 74 57 } //1 StartW
		$a_01_1 = {55 70 64 61 74 65 57 } //1 UpdateW
		$a_80_2 = {69 6d 61 67 65 73 2f 74 68 65 6d 65 2f 6c 6f 67 2e 70 68 70 } //images/theme/log.php  1
		$a_80_3 = {31 30 33 2e 32 31 33 2e 32 34 37 2e 34 38 } //103.213.247.48  1
		$a_01_4 = {44 6f 77 6e 6c 6f 61 64 2e 64 6c 6c } //1 Download.dll
		$a_01_5 = {57 69 6e 48 74 74 70 43 6f 6e 6e 65 63 74 } //1 WinHttpConnect
		$a_01_6 = {53 6c 65 65 70 } //1 Sleep
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}