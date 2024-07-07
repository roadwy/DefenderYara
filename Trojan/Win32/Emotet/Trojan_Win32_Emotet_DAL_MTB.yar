
rule Trojan_Win32_Emotet_DAL_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DAL!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 5c 24 44 8b 45 08 0f b6 cb 8a 1c 06 8a 54 0c 48 32 da 83 c4 30 88 1c 06 8b 45 0c 46 3b f0 0f 8c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}