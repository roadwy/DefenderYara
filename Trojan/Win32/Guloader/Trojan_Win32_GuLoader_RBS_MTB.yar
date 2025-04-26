
rule Trojan_Win32_GuLoader_RBS_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RBS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {2d 5c 67 72 6f 74 65 73 6b 65 73 5c 50 6c 65 74 74 65 6e 31 31 33 5c 66 6c 64 65 73 6b 75 6d 6d 65 6e } //1 -\groteskes\Pletten113\fldeskummen
		$a_81_1 = {25 73 68 75 66 66 6c 69 6e 67 6c 79 25 5c 72 65 70 6f 72 74 65 72 65 64 65 5c 4e 6f 6e 6e 61 74 69 76 65 73 } //1 %shufflingly%\reporterede\Nonnatives
		$a_81_2 = {5c 6d 61 79 6f 72 73 68 69 70 73 5c 45 70 69 64 65 6d 69 6f 6c 6f 67 69 65 6e 73 2e 69 6e 69 } //1 \mayorships\Epidemiologiens.ini
		$a_81_3 = {62 6f 64 69 63 65 64 20 70 61 6c 61 65 6f 6e 74 6f 67 72 61 70 68 79 20 61 72 62 65 6a 64 73 70 61 70 69 72 65 72 6e 65 } //1 bodiced palaeontography arbejdspapirerne
		$a_81_4 = {6b 75 6c 62 72 69 6e 74 65 72 6e 65 20 61 61 62 6e 65 6d 75 73 6b 65 6c 73 2e 65 78 65 } //1 kulbrinterne aabnemuskels.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}