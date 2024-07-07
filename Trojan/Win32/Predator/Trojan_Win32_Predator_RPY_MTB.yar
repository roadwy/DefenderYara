
rule Trojan_Win32_Predator_RPY_MTB{
	meta:
		description = "Trojan:Win32/Predator.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {50 6a 0e 8d 45 ec 83 c1 0e 50 57 89 4d ee ff d6 6a 00 8d 45 0c 50 8b 43 20 8d 04 85 28 00 00 00 50 53 57 ff d6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}