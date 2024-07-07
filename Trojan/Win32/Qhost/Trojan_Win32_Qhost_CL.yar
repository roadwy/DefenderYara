
rule Trojan_Win32_Qhost_CL{
	meta:
		description = "Trojan:Win32/Qhost.CL,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {36 39 2e 31 30 2e 35 33 2e 32 33 30 20 6f 64 6e 6f 6b 6c 61 73 73 6e 69 6b 69 2e 72 75 } //1 69.10.53.230 odnoklassniki.ru
		$a_01_1 = {36 39 2e 31 30 2e 35 33 2e 32 33 30 20 76 6b 6f 6e 74 61 6b 74 65 2e 72 75 } //1 69.10.53.230 vkontakte.ru
		$a_01_2 = {36 39 2e 31 30 2e 35 33 2e 32 33 30 20 76 6b 2e 63 6f 6d } //1 69.10.53.230 vk.com
		$a_01_3 = {65 63 68 6f 20 22 25 57 49 4e 44 49 52 25 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 22 } //1 echo "%WINDIR%\system32\drivers\etc\hosts"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}