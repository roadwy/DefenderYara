
rule Trojan_Win32_CryptInject_CY_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.CY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4e 74 54 65 72 6d 69 6e 61 74 65 2e 65 78 65 } //1 NtTerminate.exe
		$a_01_1 = {49 2e 4c 4f 56 45 2e 59 4f 55 2e 74 78 74 2e 76 62 73 } //1 I.LOVE.YOU.txt.vbs
		$a_01_2 = {76 6d 77 61 72 65 } //1 vmware
		$a_01_3 = {5b 69 20 4c 6f 76 65 20 59 6f 75 5d } //1 [i Love You]
		$a_01_4 = {73 61 6e 64 62 6f 78 } //1 sandbox
		$a_01_5 = {61 72 72 61 79 53 65 72 76 69 63 65 2e 74 78 74 } //1 arrayService.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}