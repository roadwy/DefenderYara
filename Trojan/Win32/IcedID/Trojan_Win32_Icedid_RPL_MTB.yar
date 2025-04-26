
rule Trojan_Win32_Icedid_RPL_MTB{
	meta:
		description = "Trojan:Win32/Icedid.RPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {53 bf e0 07 00 00 29 7d d0 6a 40 68 00 30 00 00 57 53 ff 75 c4 ff 55 84 8b 4d d0 8b 55 cc 03 ca 57 51 50 89 45 c0 ff 55 9c 83 c4 0c 53 6a 40 68 00 30 00 00 ff 75 d0 53 ff 75 c4 ff 55 84 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}