
rule Trojan_Win32_Lolopak_A_MSR{
	meta:
		description = "Trojan:Win32/Lolopak.A!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {b9 ff ff 0f 00 6a 00 89 2c 24 33 ed 33 ab ?? ?? ?? ?? 8b c5 5d 68 ?? ?? ?? ?? 8f 83 ?? ?? ?? ?? 21 8b ?? ?? ?? ?? 33 83 ?? ?? ?? ?? ff e0 } //1
		$a_00_1 = {6d 73 69 6d 67 33 32 2e 70 64 62 } //1 msimg32.pdb
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}