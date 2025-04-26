
rule Trojan_Win32_Venik_SIB_MTB{
	meta:
		description = "Trojan:Win32/Venik.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 f8 ff 74 ?? 3b c6 7e ?? 53 8d 85 ?? ?? ?? ?? 56 50 e8 ?? ?? ?? ?? [0-05] 8d 85 90 1b 02 56 53 50 8b 45 ?? ff 70 ?? ff 15 ?? ?? ?? ?? 8b f8 3b fe 7e ?? 8d 85 90 1b 02 57 50 90 18 8b 44 24 ?? 33 c9 39 4c 24 ?? 7e ?? 8a 14 01 80 ea ?? 80 f2 ?? 88 14 01 41 3b 4c 24 90 1b 0d 7c } //1
		$a_02_1 = {8b 44 24 04 33 c9 39 4c 24 ?? 7e ?? 8a 14 01 80 f2 ?? 80 c2 ?? 88 14 01 41 3b 4c 24 90 1b 00 7c } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}