
rule Trojan_Win32_Zbot_SIBD25_MTB{
	meta:
		description = "Trojan:Win32/Zbot.SIBD25!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b9 00 00 00 00 90 18 b8 90 01 04 90 18 30 07 90 18 41 90 18 47 90 18 39 f1 90 18 90 18 30 07 90 18 41 90 18 47 90 18 39 f1 90 18 72 90 01 01 90 18 90 18 58 90 18 ff e0 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}