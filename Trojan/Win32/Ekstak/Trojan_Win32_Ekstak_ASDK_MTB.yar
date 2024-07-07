
rule Trojan_Win32_Ekstak_ASDK_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASDK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {53 56 57 68 48 b1 4c 00 68 38 b1 4c 00 ff 15 90 02 03 00 8b 3d 04 93 4c 00 68 e8 b0 4c 00 8b f0 ff d7 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}