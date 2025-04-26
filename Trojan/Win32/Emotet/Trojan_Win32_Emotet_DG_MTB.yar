
rule Trojan_Win32_Emotet_DG_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_81_0 = {4a 49 4f 4e 64 33 6b 61 40 3e 42 72 54 5e 7a 53 46 6c 65 44 67 78 34 47 47 } //3 JIONd3ka@>BrT^zSFleDgx4GG
		$a_81_1 = {47 65 74 54 65 6d 70 46 69 6c 65 4e 61 6d 65 41 } //3 GetTempFileNameA
		$a_81_2 = {47 65 74 54 65 6d 70 50 61 74 68 41 } //3 GetTempPathA
		$a_81_3 = {44 65 6c 65 74 65 46 69 6c 65 41 } //3 DeleteFileA
		$a_81_4 = {5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c } //3 \shell\open\
		$a_81_5 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //3 DllRegisterServer
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3) >=18
 
}