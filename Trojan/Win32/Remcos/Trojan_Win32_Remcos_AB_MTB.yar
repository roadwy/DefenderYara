
rule Trojan_Win32_Remcos_AB_MTB{
	meta:
		description = "Trojan:Win32/Remcos.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 03 00 00 0a 00 "
		
	strings :
		$a_00_0 = {0f b6 19 46 33 de 3b df 75 f6 } //03 00 
		$a_80_1 = {73 72 62 6c 7a 62 63 69 6b 6c } //srblzbcikl  03 00 
		$a_80_2 = {6b 79 74 68 64 69 67 75 6c } //kythdigul  00 00 
	condition:
		any of ($a_*)
 
}