
rule Trojan_Win32_Remcos_ARMS_MTB{
	meta:
		description = "Trojan:Win32/Remcos.ARMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 c4 18 8d 45 f0 50 8d 45 a8 50 57 57 68 00 00 00 08 57 57 57 68 58 89 46 00 68 dc 89 46 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}