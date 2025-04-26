
rule Trojan_Win32_Zlob_gen_J{
	meta:
		description = "Trojan:Win32/Zlob.gen!J,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_02_0 = {80 fa 41 75 03 6a 0a 59 80 fa ?? 75 ?? ?? [0-02] 80 fa ?? 75 03 ?? ?? ?? 80 fa ?? 75 } //1
		$a_02_1 = {41 75 06 66 c7 45 f4 0a 00 0f be ?? f3 83 ?? ?? 75 06 66 c7 45 f4 ?? 00 0f be ?? f3 83 ?? ?? 75 06 66 c7 45 f4 ?? 00 0f be ?? f3 83 ?? ?? 75 06 90 09 02 00 83 } //1
		$a_02_2 = {83 ea 57 0f b7 d2 8a d9 80 eb ?? 80 fb ?? 77 ?? 66 0f be d1 66 ?? ?? [0-01] 0f b7 d2 8a d9 ?? ?? ?? ?? ?? [0-01] 77 ?? 66 0f be d1 66 ?? ?? [0-01] 0f b7 d2 8a d9 } //1
		$a_02_3 = {83 e9 57 0f b7 c9 8a d0 80 ea ?? 80 fa ?? 77 0b 66 0f be c8 66 83 e9 ?? 0f b7 c9 8a d0 80 ea ?? 80 fa ?? 77 0b 66 0f be c8 66 83 e9 ?? 0f b7 c9 8a d0 } //1
		$a_02_4 = {83 e9 57 0f b7 c9 3c ?? 7c 0f 3c ?? 7f 0b 66 0f be d0 66 83 ea ?? 0f b7 ca 3c ?? 7c 0f 3c ?? 7f 0b 66 0f be ?? 66 (2d|83 e9) } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1) >=1
 
}