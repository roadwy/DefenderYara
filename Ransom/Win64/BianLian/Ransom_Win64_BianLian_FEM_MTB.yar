
rule Ransom_Win64_BianLian_FEM_MTB{
	meta:
		description = "Ransom:Win64/BianLian.FEM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 58 89 84 24 88 00 00 00 48 8b ac 24 a0 00 00 00 4c 0f be 7d 00 48 63 84 24 88 00 00 00 49 31 c7 4c 89 f8 50 48 8b ac 24 a8 00 00 00 58 88 45 00 4c 8b bc 24 a0 00 00 00 49 ff c7 4c 89 bc 24 a0 00 00 00 ff 44 24 78 } //5
		$a_01_1 = {62 63 64 65 64 69 74 2e 65 78 65 20 2f 73 65 74 20 6c 6f 61 64 6f 70 74 69 6f 6e 73 20 44 44 49 53 41 42 4c 45 5f 49 4e 54 45 47 52 49 54 59 5f 43 48 45 43 4b 53 } //1 bcdedit.exe /set loadoptions DDISABLE_INTEGRITY_CHECKS
		$a_01_2 = {73 63 20 63 72 65 61 74 65 20 77 69 6e 70 70 78 20 62 69 6e 50 61 74 68 } //1 sc create winppx binPath
		$a_81_3 = {72 65 76 73 6f 6b 73 2e 62 61 74 } //1 revsoks.bat
		$a_01_4 = {5a 7a 31 35 38 64 66 40 6a 6e 69 6f 77 34 35 68 40 } //1 Zz158df@jniow45h@
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}