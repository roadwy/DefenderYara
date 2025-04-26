
rule Ransom_Win32_Embargo_A{
	meta:
		description = "Ransom:Win32/Embargo.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {f3 0f 6f 48 f0 f3 0f 6f 10 66 0f ef c8 66 0f ef d0 f3 0f 7f 48 f0 f3 0f 7f 10 83 c0 20 83 c6 e0 75 de } //2
		$a_03_1 = {65 6d 62 61 72 67 6f 3a 3a [0-30] 2f 65 6e 63 72 79 70 74 2e 72 73 } //2
		$a_01_2 = {62 63 64 65 64 69 74 2f 73 65 74 7b 64 65 66 61 75 6c 74 7d 72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 6e 6f } //1 bcdedit/set{default}recoveryenabledno
		$a_01_3 = {43 72 79 70 74 43 6f 6e 66 69 67 65 78 74 65 6e 73 69 6f 6e 6e 6f 74 65 5f 6e 61 6d 65 70 75 62 6c 69 63 5f 6b 65 79 6e 6f 74 65 5f 63 6f 6e 74 65 6e 74 73 65 78 63 6c 75 64 65 5f 70 61 74 68 73 66 75 6c 6c 5f 65 6e 63 72 79 70 74 5f 65 78 74 65 6e 73 69 6f 6e 73 } //1 CryptConfigextensionnote_namepublic_keynote_contentsexclude_pathsfull_encrypt_extensions
		$a_01_4 = {6b 69 6c 6c 5f 73 65 72 76 69 63 65 73 6b 69 6c 6c 5f 70 72 6f 63 73 76 6d 5f 65 78 74 65 6e 73 69 6f 6e 73 65 78 63 6c 75 64 65 64 5f 76 6d 73 63 72 65 64 73 70 72 69 76 61 74 65 5f 6b 65 79 } //1 kill_serviceskill_procsvm_extensionsexcluded_vmscredsprivate_key
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}