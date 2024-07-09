
rule Trojan_Win32_Jaik_GNS_MTB{
	meta:
		description = "Trojan:Win32/Jaik.GNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {34 d8 13 0d ?? ?? ?? ?? 31 2b 79 31 f3 5a 8a c4 d0 c3 } //10
		$a_01_1 = {62 34 76 4e 69 52 37 43 61 } //1 b4vNiR7Ca
		$a_01_2 = {50 2e 76 6d 70 30 } //1 P.vmp0
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}