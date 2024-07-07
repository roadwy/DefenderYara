
rule Trojan_Win32_Phorpiex_CRTF_MTB{
	meta:
		description = "Trojan:Win32/Phorpiex.CRTF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {ba 68 00 00 00 66 89 95 5c f9 ff ff b8 74 00 00 00 66 89 85 5e f9 ff ff b9 74 00 00 00 66 89 8d 60 f9 ff ff ba 70 00 00 00 66 89 95 62 f9 ff ff b8 3a 00 00 00 66 89 85 64 f9 ff ff b9 2f 00 00 00 66 89 8d 66 f9 ff ff } //1
		$a_01_1 = {ba 2f 00 00 00 66 89 95 68 f9 ff ff b8 31 00 00 00 66 89 85 6a f9 ff ff b9 38 00 00 00 66 89 8d 6c f9 ff ff ba 35 00 00 00 66 89 95 6e f9 ff ff b8 2e 00 00 00 66 89 85 70 f9 ff ff b9 32 00 00 00 66 89 8d 72 f9 ff ff } //1
		$a_01_2 = {ba 31 00 00 00 66 89 95 74 f9 ff ff b8 35 00 00 00 66 89 85 76 f9 ff ff b9 2e 00 00 00 66 89 8d 78 f9 ff ff ba 31 00 00 00 66 89 95 7a f9 ff ff b8 31 00 00 00 66 89 85 7c f9 ff ff b9 33 00 00 00 66 89 8d 7e f9 ff ff } //1
		$a_01_3 = {ba 2e 00 00 00 66 89 95 80 f9 ff ff b8 38 00 00 00 66 89 85 82 f9 ff ff b9 34 00 00 00 66 89 8d 84 f9 ff ff ba 2f 00 00 00 66 89 95 86 f9 ff ff b8 70 00 00 00 66 89 85 88 f9 ff ff b9 70 00 00 00 66 89 8d 8a f9 ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}