
rule Trojan_Win32_Convagent_AMAQ_MTB{
	meta:
		description = "Trojan:Win32/Convagent.AMAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c6 59 8a 4d ?? 30 08 46 3b f7 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}