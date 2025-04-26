
rule Trojan_Win32_Azorult_RPD_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6b c0 4c 6b f0 62 8b 45 0c 8b 4d f4 0f be 14 08 31 f2 88 14 08 8b 45 f4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}