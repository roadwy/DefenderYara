
rule Trojan_Win32_CryptInject_PAAN_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.PAAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 77 77 77 2e 77 6a 6d 73 68 6f 6d 65 2e 63 6f 6d 2f 53 65 63 72 65 74 43 68 61 74 2e 68 74 6d } //1 ://www.wjmshome.com/SecretChat.htm
		$a_01_1 = {5c 6a 69 61 6d 69 2e 65 78 65 } //1 \jiami.exe
		$a_01_2 = {57 69 6e 53 74 61 30 5c 44 65 66 61 75 6c 74 } //1 WinSta0\Default
		$a_01_3 = {41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //1 Applications\iexplore.exe\shell\open\command
		$a_01_4 = {48 41 52 44 57 41 52 45 5c 44 45 53 43 52 49 50 54 49 4f 4e 5c 53 79 73 74 65 6d 5c 43 65 6e 74 72 61 6c 50 72 6f 63 65 73 73 6f 72 5c 30 } //1 HARDWARE\DESCRIPTION\System\CentralProcessor\0
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}