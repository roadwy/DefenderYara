
rule Trojan_BAT_Zusy_EC_MTB{
	meta:
		description = "Trojan:BAT/Zusy.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {25 16 1f 2d 9d 6f a4 00 00 0a 0c 08 16 9a 28 16 00 00 0a 08 17 9a 08 18 9a } //5
		$a_01_1 = {43 65 6e 73 6f 49 42 47 45 2e 52 65 6d 6f 76 65 43 61 64 61 73 74 72 6f 2e 72 65 73 6f 75 72 63 65 73 } //2 CensoIBGE.RemoveCadastro.resources
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2) >=7
 
}
rule Trojan_BAT_Zusy_EC_MTB_2{
	meta:
		description = "Trojan:BAT/Zusy.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 "
		
	strings :
		$a_81_0 = {75 6e 6b 6e 6f 77 6e 73 70 66 5f 6c 6f 61 64 65 72 } //5 unknownspf_loader
		$a_81_1 = {61 68 64 6b 61 6b 68 64 32 6f 69 61 75 7a 64 39 61 38 64 75 30 61 32 64 75 61 32 30 39 64 75 61 32 38 39 64 75 61 32 39 38 30 64 75 61 32 39 30 38 64 75 61 32 39 64 75 61 39 32 64 75 61 39 64 75 39 61 32 64 75 7a } //5 ahdkakhd2oiauzd9a8du0a2dua209dua289dua2980dua2908dua29dua92dua9du9a2duz
		$a_81_2 = {64 65 6c 20 2f 73 20 2f 66 20 2f 71 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 50 72 65 66 65 74 63 68 } //1 del /s /f /q C:\Windows\Prefetch
		$a_81_3 = {4e 54 45 75 4f 44 6b 75 4e 79 34 7a 4d 77 3d 3d } //1 NTEuODkuNy4zMw==
		$a_81_4 = {64 65 61 63 74 69 76 61 74 69 6f 6e 2e 70 68 70 3f 68 61 73 68 3d } //1 deactivation.php?hash=
		$a_81_5 = {61 63 74 69 76 61 74 69 6f 6e 2e 70 68 70 3f 63 6f 64 65 3d } //1 activation.php?code=
	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*5+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=14
 
}