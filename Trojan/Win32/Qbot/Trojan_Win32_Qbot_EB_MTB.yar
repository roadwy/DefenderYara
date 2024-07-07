
rule Trojan_Win32_Qbot_EB_MTB{
	meta:
		description = "Trojan:Win32/Qbot.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 d2 03 04 24 13 54 24 04 83 c4 08 } //3
		$a_01_1 = {29 04 24 19 54 24 04 58 5a 2b d8 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}
rule Trojan_Win32_Qbot_EB_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 45 a4 8b 45 d8 8b 55 a8 01 10 8b 45 c4 03 45 a4 89 45 a0 6a 00 e8 90 01 04 03 45 a0 40 8b 55 d8 33 02 89 45 a0 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Qbot_EB_MTB_3{
	meta:
		description = "Trojan:Win32/Qbot.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {70 69 62 69 63 6f 6e 76 5f 73 65 74 5f 72 65 6c 6f 63 61 74 69 6f 6e 5f 70 72 65 66 69 78 } //1 pibiconv_set_relocation_prefix
		$a_01_1 = {4d 53 5f 4b 41 4e 4a 49 } //1 MS_KANJI
		$a_01_2 = {57 49 4e 42 41 4c 54 52 49 4d } //1 WINBALTRIM
		$a_01_3 = {23 62 23 64 23 66 23 68 23 6a 23 6c 23 6e 23 70 23 72 23 74 23 76 23 78 23 7a 23 7c 23 7e 23 } //1 #b#d#f#h#j#l#n#p#r#t#v#x#z#|#~#
		$a_01_4 = {70 63 6f 6e 76 5f 63 61 6e 6f 6e 69 63 61 6c 69 7a 65 } //1 pconv_canonicalize
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Qbot_EB_MTB_4{
	meta:
		description = "Trojan:Win32/Qbot.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {51 00 49 00 61 00 4b 00 48 00 48 00 64 00 49 00 61 00 65 00 79 00 7a 00 56 00 79 00 4d 00 70 00 4b 00 4b 00 64 00 44 00 6a 00 57 00 4a 00 50 00 4d 00 54 00 68 00 4e 00 4a 00 6a 00 6d 00 56 00 69 00 } //1 QIaKHHdIaeyzVyMpKKdDjWJPMThNJjmVi
		$a_01_1 = {69 00 62 00 64 00 57 00 56 00 6c 00 5a 00 42 00 43 00 6d 00 48 00 50 00 4c 00 61 00 6c 00 44 00 66 00 47 00 70 00 50 00 47 00 6d 00 46 00 57 00 50 00 76 00 63 00 65 00 65 00 54 00 43 00 54 00 59 00 } //1 ibdWVlZBCmHPLalDfGpPGmFWPvceeTCTY
		$a_01_2 = {6e 00 66 00 4f 00 54 00 4c 00 6c 00 53 00 66 00 73 00 4a 00 } //1 nfOTLlSfsJ
		$a_01_3 = {7a 00 72 00 7a 00 4b 00 76 00 6b 00 55 00 62 00 48 00 65 00 79 00 6e 00 54 00 54 00 4d 00 74 00 47 00 } //1 zrzKvkUbHeynTTMtG
		$a_01_4 = {4b 00 50 00 62 00 6f 00 56 00 6b 00 76 00 } //1 KPboVkv
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}