
rule Trojan_Win32_Slepak_DEB_MTB{
	meta:
		description = "Trojan:Win32/Slepak.DEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 02 0f 46 d9 05 ac 1a 06 01 81 3d 90 01 04 73 0f 00 00 a3 90 01 04 89 02 75 09 2b 3d 90 01 04 83 de 00 83 c2 04 83 6c 24 0c 01 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}