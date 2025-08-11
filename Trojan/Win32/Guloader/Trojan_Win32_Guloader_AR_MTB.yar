
rule Trojan_Win32_Guloader_AR_MTB{
	meta:
		description = "Trojan:Win32/Guloader.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {43 6f 6c 6f 62 69 75 6d 32 39 5c 4e 6f 6d 61 64 65 6e 2e 64 6c 6c } //1 Colobium29\Nomaden.dll
		$a_01_1 = {6d 61 64 6c 61 76 6e 69 6e 67 73 73 6b 72 69 62 65 6e 74 65 72 5c 6c 69 70 6f 74 72 6f 70 79 2e 69 6e 69 } //1 madlavningsskribenter\lipotropy.ini
		$a_01_2 = {52 65 63 6f 72 70 6f 72 69 66 79 5c 65 6e 68 6a 72 6e 69 6e 67 73 2e 69 6e 69 } //1 Recorporify\enhjrnings.ini
		$a_01_3 = {52 65 6e 6f 6d 6d 65 65 72 73 5c 54 6f 62 61 6b 73 61 73 6b 65 73 2e 62 69 6e } //1 Renommeers\Tobaksaskes.bin
		$a_01_4 = {6f 72 67 61 73 6d 65 72 6e 65 2e 69 6e 69 } //1 orgasmerne.ini
		$a_01_5 = {73 6b 6f 76 68 75 67 73 74 65 6e 5c 78 69 70 68 6f 70 61 67 6f 75 73 2e 68 74 6d } //1 skovhugsten\xiphopagous.htm
		$a_01_6 = {52 61 6d 6d 65 6c 6f 76 65 73 32 32 32 2e 69 6e 69 } //1 Rammeloves222.ini
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}