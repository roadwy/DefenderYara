
rule Trojan_Win32_TrickBotCrypt_DU_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.DU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {4f 4a 4a 65 68 74 3f 65 79 52 53 32 6c 6d 3c 39 4e 57 31 38 78 6c 68 61 69 53 30 36 4d 6b 4a 6e 4d 33 4d 36 49 4f 5f 7a } //1 OJJeht?eyRS2lm<9NW18xlhaiS06MkJnM3M6IO_z
		$a_81_1 = {46 75 63 6b 20 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 } //1 Fuck Windows Defender
		$a_81_2 = {53 74 61 72 74 57 } //1 StartW
		$a_81_3 = {73 63 2e 65 78 65 } //1 sc.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}