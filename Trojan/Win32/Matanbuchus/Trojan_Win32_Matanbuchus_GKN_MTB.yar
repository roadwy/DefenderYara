
rule Trojan_Win32_Matanbuchus_GKN_MTB{
	meta:
		description = "Trojan:Win32/Matanbuchus.GKN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 45 ff 64 a1 30 00 00 00 53 56 57 8b 40 0c 8b 40 0c 8b 50 18 8b 4a 3c 8b 4c 11 78 03 ca } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}