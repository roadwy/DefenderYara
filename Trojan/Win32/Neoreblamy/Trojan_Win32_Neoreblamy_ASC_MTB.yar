
rule Trojan_Win32_Neoreblamy_ASC_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.ASC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 64 6c 54 78 68 41 74 52 66 4b 6f 4b 53 5a 64 4e 79 4c 6d 44 6e 42 7a 42 65 6c 71 69 } //1 WdlTxhAtRfKoKSZdNyLmDnBzBelqi
		$a_01_1 = {44 4d 44 71 72 6c 79 78 54 51 79 6c 50 42 44 45 67 71 66 41 6b 45 45 5a 73 64 42 74 7a } //1 DMDqrlyxTQylPBDEgqfAkEEZsdBtz
		$a_01_2 = {59 69 54 54 4b 45 55 7a 64 44 4f 4c 4e 74 4f 4a 4e 48 56 4c 65 48 76 6d 78 4f 72 64 4d } //1 YiTTKEUzdDOLNtOJNHVLeHvmxOrdM
		$a_01_3 = {47 55 6b 4b 65 4a 50 69 6b 45 7a 49 49 76 6e 53 48 6d 41 4e 48 41 65 6a 75 } //1 GUkKeJPikEzIIvnSHmANHAeju
		$a_01_4 = {6d 75 6b 78 4e 67 52 53 79 51 66 47 74 45 56 41 69 48 5a 44 77 5a 48 53 63 56 74 43 6f 44 6d 6b 7a 61 } //1 mukxNgRSyQfGtEVAiHZDwZHScVtCoDmkza
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}