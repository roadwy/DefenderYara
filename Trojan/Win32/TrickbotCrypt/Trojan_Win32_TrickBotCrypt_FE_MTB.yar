
rule Trojan_Win32_TrickBotCrypt_FE_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.FE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {0f b6 08 0f b6 95 ?? ?? ?? ?? 33 ca 8b 85 ?? ?? ?? ?? 2b 85 ?? ?? ?? ?? 0f b6 d0 81 e2 80 ?? ?? ?? 33 ca 8b 85 ?? ?? ?? ?? 88 08 } //1
		$a_81_1 = {44 45 48 55 47 48 20 45 42 53 54 20 59 44 55 53 49 4a 42 44 53 20 4f 46 44 55 49 46 56 44 47 53 48 42 } //1 DEHUGH EBST YDUSIJBDS OFDUIFVDGSHB
		$a_81_2 = {6a 6f 65 62 6f 78 63 6f 6e 74 72 6f 6c 2e 65 78 65 } //1 joeboxcontrol.exe
		$a_81_3 = {6a 6f 65 62 6f 78 73 65 72 76 65 72 2e 65 78 65 } //1 joeboxserver.exe
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}