
rule Trojan_Win32_CobaltStrike_XZ_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.XZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {64 a1 30 00 00 00 8b 40 0c 8b 40 14 8b 00 8b 40 10 c3 } //1
		$a_01_1 = {6c 69 62 45 47 4c 2e 64 6c 6c 2e 70 64 62 } //1 libEGL.dll.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}