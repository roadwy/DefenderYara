
rule Trojan_Win32_GuLoader_RSN_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RSN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {35 5c 62 65 64 76 65 6c 73 65 6e 73 5c 52 65 61 63 63 65 6c 65 72 61 74 65 73 2e 73 6b 65 } //1 5\bedvelsens\Reaccelerates.ske
		$a_81_1 = {6c 6f 64 64 65 62 6f 6c 74 5c 4e 65 77 73 64 65 61 6c 65 72 73 } //1 loddebolt\Newsdealers
		$a_81_2 = {25 62 69 6f 73 79 6e 74 68 65 73 69 7a 65 25 5c 6d 75 6c 74 69 70 61 72 74 69 74 65 5c 73 69 67 76 61 72 64 } //1 %biosynthesize%\multipartite\sigvard
		$a_81_3 = {5c 72 65 74 73 6b 72 69 76 6e 69 6e 67 73 72 65 67 6c 65 6e 73 5c 64 6f 6d 65 73 74 69 6b 76 72 65 6c 73 65 73 2e 69 6e 69 } //1 \retskrivningsreglens\domestikvrelses.ini
		$a_81_4 = {62 6a 65 72 67 62 65 73 74 69 67 6e 69 6e 67 65 72 6e 65 } //1 bjergbestigningerne
		$a_81_5 = {76 75 6c 67 61 72 69 7a 65 72 2e 65 78 65 } //1 vulgarizer.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}