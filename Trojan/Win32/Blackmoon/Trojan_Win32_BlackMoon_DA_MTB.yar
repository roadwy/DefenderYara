
rule Trojan_Win32_BlackMoon_DA_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,66 00 66 00 05 00 00 "
		
	strings :
		$a_81_0 = {2f 2f 76 69 70 2e 31 32 33 70 61 6e 2e 63 6e 2f } //100 //vip.123pan.cn/
		$a_81_1 = {63 6d 64 20 2f 63 20 64 65 6c 20 25 54 65 6d 70 25 } //1 cmd /c del %Temp%
		$a_81_2 = {2e 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 } //1 .Net.WebClient).D
		$a_81_3 = {53 68 65 6c 6c 45 78 65 63 75 74 65 45 78 57 } //1 ShellExecuteExW
		$a_81_4 = {43 72 79 70 74 44 65 73 74 72 6f 79 48 61 73 68 } //1 CryptDestroyHash
	condition:
		((#a_81_0  & 1)*100+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=102
 
}