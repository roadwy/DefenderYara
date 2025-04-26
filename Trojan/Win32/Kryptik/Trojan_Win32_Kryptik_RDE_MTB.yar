
rule Trojan_Win32_Kryptik_RDE_MTB{
	meta:
		description = "Trojan:Win32/Kryptik.RDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {4f 6e 65 4e 65 6f } //1 OneNeo
		$a_01_1 = {54 77 6f 4e 65 6f } //1 TwoNeo
		$a_01_2 = {54 68 72 4e 65 6f } //1 ThrNeo
		$a_01_3 = {74 69 64 74 63 66 76 79 2e 64 6c 6c } //1 tidtcfvy.dll
		$a_03_4 = {8a 06 46 53 83 c4 04 89 c0 32 02 68 ?? ?? ?? ?? 83 c4 04 88 07 47 83 ec 04 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*2) >=6
 
}