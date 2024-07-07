
rule Trojan_Win32_Azorult_RPG_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 45 dc 89 45 f8 33 c7 31 45 fc 8b 45 f0 89 45 e4 8b 45 fc 29 45 e4 8b 45 e4 89 45 f0 8b 45 c4 29 45 f4 ff 4d d8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}