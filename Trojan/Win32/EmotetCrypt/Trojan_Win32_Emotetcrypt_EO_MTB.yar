
rule Trojan_Win32_Emotetcrypt_EO_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.EO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_81_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //10 DllRegisterServer
		$a_81_1 = {6e 33 66 65 71 66 63 39 71 64 2e 64 6c 6c } //1 n3feqfc9qd.dll
		$a_81_2 = {63 79 32 35 62 76 77 62 6c 7a 35 65 65 66 68 71 61 6a 35 69 6f 75 7a 76 36 39 33 6c 65 } //1 cy25bvwblz5eefhqaj5iouzv693le
		$a_81_3 = {65 6f 31 6a 66 31 65 6b 6f 75 6b 6a 6d 64 76 68 6c 6e 39 34 38 39 70 68 } //1 eo1jf1ekoukjmdvhln9489ph
		$a_81_4 = {64 79 35 64 75 39 6c 6a 6e 6e 6b 61 7a 63 62 71 30 75 77 62 } //1 dy5du9ljnnkazcbq0uwb
		$a_81_5 = {78 72 6f 30 72 75 72 33 69 75 6a 6e 76 74 6f 77 7a 7a 33 32 62 76 6a 34 67 73 76 32 35 77 78 } //1 xro0rur3iujnvtowzz32bvj4gsv25wx
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=15
 
}