
rule Ransom_Win32_Ryuk_A_{
	meta:
		description = "Ransom:Win32/Ryuk.A!!Ryuk.SD!MTB,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_81_0 = {52 79 75 6b 52 65 61 64 4d 65 2e 68 74 6d 6c } //1 RyukReadMe.html
		$a_81_1 = {3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 6e 65 74 2e 65 78 65 22 20 73 74 6f 70 20 22 73 61 6d 73 73 22 } //1 :\Windows\System32\net.exe" stop "samss"
		$a_81_2 = {6c 69 73 6d 6f 76 61 63 6f 6c 31 39 38 31 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //1 lismovacol1981@protonmail.com
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=2
 
}