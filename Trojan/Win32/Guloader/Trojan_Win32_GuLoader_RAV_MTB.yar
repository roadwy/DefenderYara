
rule Trojan_Win32_GuLoader_RAV_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {5c 63 6f 6e 74 61 6d 69 6e 61 74 69 6f 6e 73 5c 64 72 69 6c 6c 65 73 79 67 65 73 74 65 } //1 \contaminations\drillesygeste
		$a_81_1 = {25 72 65 6e 6e 61 73 65 73 25 5c 69 6e 64 6f 63 69 62 6c 65 6e 65 73 73 5c 66 69 6e 61 6e 73 6d 69 6e 69 73 74 72 65 6e 65 73 } //1 %rennases%\indocibleness\finansministrenes
		$a_81_2 = {25 73 69 64 79 25 5c 6d 79 67 67 65 73 5c 56 69 64 6e 65 61 66 68 72 69 6e 67 65 72 73 } //1 %sidy%\mygges\Vidneafhringers
		$a_81_3 = {61 73 65 6c 6c 61 74 65 5c 4d 75 6d 6d 65 72 79 31 31 39 2e 65 78 65 } //1 asellate\Mummery119.exe
		$a_81_4 = {5c 62 6f 6c 73 6a 65 72 73 5c 49 6e 64 6c 73 65 6e 64 65 73 2e 69 6e 69 } //1 \bolsjers\Indlsendes.ini
		$a_81_5 = {5c 6e 61 72 72 65 6e 65 5c 4b 61 72 74 65 75 73 65 72 31 32 35 2e 64 6c 6c } //1 \narrene\Karteuser125.dll
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}