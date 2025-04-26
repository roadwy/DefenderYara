
rule Trojan_BAT_Azorult_ABM_MTB{
	meta:
		description = "Trojan:BAT/Azorult.ABM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 09 00 00 "
		
	strings :
		$a_80_0 = {21 48 6f 73 74 20 50 72 6f 63 65 73 73 20 66 6f 72 20 57 69 6e 64 6f 77 73 20 53 65 72 76 69 63 65 73 } //!Host Process for Windows Services  3
		$a_80_1 = {43 6f 6e 66 75 73 65 72 2e 43 6f 72 65 20 31 2e 36 2e 30 2d 61 6c 70 68 61 } //Confuser.Core 1.6.0-alpha  3
		$a_80_2 = {42 6c 6f 63 6b 43 6f 70 79 } //BlockCopy  3
		$a_80_3 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //set_UseShellExecute  3
		$a_80_4 = {61 64 64 5f 41 73 73 65 6d 62 6c 79 52 65 73 6f 6c 76 65 } //add_AssemblyResolve  3
		$a_80_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  3
		$a_80_6 = {49 73 4c 69 74 74 6c 65 45 6e 64 69 61 6e } //IsLittleEndian  3
		$a_80_7 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //CreateDecryptor  3
		$a_80_8 = {52 66 63 32 38 39 38 44 65 72 69 76 65 42 79 74 65 73 } //Rfc2898DeriveBytes  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3+(#a_80_8  & 1)*3) >=24
 
}