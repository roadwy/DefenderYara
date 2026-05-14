
rule Trojan_Win32_GuLoader_REB_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.REB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {5c 4f 72 69 67 69 6e 61 6c 69 74 65 74 65 6e 73 32 31 33 5c 42 69 6e 6f 63 6c 65 31 38 32 5c 6e 6f 6e 61 65 73 74 68 65 74 69 63 61 6c 6c 79 } //1 \Originalitetens213\Binocle182\nonaesthetically
		$a_81_1 = {25 6e 6f 6e 64 72 79 69 6e 67 25 5c 52 75 6d 73 6f 6e 64 65 72 6e 65 73 5c 63 6c 61 74 68 72 61 63 65 61 65 } //1 %nondrying%\Rumsondernes\clathraceae
		$a_81_2 = {66 65 72 74 69 6c 69 73 65 73 20 67 6c 6f 73 73 6f 6c 6f 67 69 65 73 } //1 fertilises glossologies
		$a_81_3 = {6d 6f 64 65 72 73 6b 61 62 65 74 } //1 moderskabet
		$a_81_4 = {70 68 6f 74 6f 6e 61 73 74 69 63 20 61 72 61 62 69 73 65 64 2e 65 78 65 } //1 photonastic arabised.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}