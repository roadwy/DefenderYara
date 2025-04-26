
rule Trojan_Win32_Remcos_RGU_MTB{
	meta:
		description = "Trojan:Win32/Remcos.RGU!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 0c 90 8b 45 14 8b 55 fc 33 0c 90 8b 45 08 8b 55 f8 89 0c 90 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}