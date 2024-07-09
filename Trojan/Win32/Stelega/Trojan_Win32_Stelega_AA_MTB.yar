
rule Trojan_Win32_Stelega_AA_MTB{
	meta:
		description = "Trojan:Win32/Stelega.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {6a 40 68 05 1a 00 00 68 00 f0 40 00 ff 55 fc 6a 00 68 00 f0 40 00 6a 00 ff 55 d4 } //1
		$a_03_1 = {8b 55 d0 83 c2 01 89 55 d0 81 7d d0 05 1a 00 00 0f 83 ?? ?? ?? ?? 8b 45 d0 8a 88 00 f0 40 00 88 4d df } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}