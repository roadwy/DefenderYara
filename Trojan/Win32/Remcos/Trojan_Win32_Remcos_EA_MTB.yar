
rule Trojan_Win32_Remcos_EA_MTB{
	meta:
		description = "Trojan:Win32/Remcos.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 9c 07 49 9e 00 00 88 1c 30 81 f9 8d 00 00 00 75 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}