
rule Trojan_Win32_Ekstak_CA_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {84 c0 75 14 a1 90 01 04 8b 90 01 01 0c 03 90 01 01 03 90 01 01 8a 90 01 05 30 90 01 01 83 3d 90 01 04 03 76 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}