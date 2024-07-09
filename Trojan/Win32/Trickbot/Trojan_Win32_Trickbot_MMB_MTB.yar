
rule Trojan_Win32_Trickbot_MMB_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.MMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {0a d3 22 d0 8b 44 24 ?? 88 14 08 40 89 44 24 ?? 3b 44 24 } //1
		$a_80_1 = {41 6c 6c 6f 63 45 78 4e 75 6d 61 } //AllocExNuma  1
		$a_80_2 = {61 4b 45 52 4e 45 4c 33 32 2e 44 4c 4c } //aKERNEL32.DLL  1
	condition:
		((#a_02_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}