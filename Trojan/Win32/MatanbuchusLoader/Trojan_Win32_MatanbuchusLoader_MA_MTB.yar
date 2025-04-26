
rule Trojan_Win32_MatanbuchusLoader_MA_MTB{
	meta:
		description = "Trojan:Win32/MatanbuchusLoader.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b ec 81 ec dc 04 00 00 33 c0 88 45 f6 8d 4d f6 e8 ea d6 ff ff 89 45 a0 8b 4d a0 0f b6 51 0c 85 d2 74 1e } //1
		$a_01_1 = {3f 48 61 63 6b 43 68 65 63 6b 40 40 59 47 58 58 5a } //1 ?HackCheck@@YGXXZ
		$a_01_2 = {44 6c 6c 49 6e 73 74 61 6c 6c } //1 DllInstall
		$a_01_3 = {36 30 30 31 2e 69 63 6c } //1 6001.icl
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}