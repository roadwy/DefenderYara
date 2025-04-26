
rule Trojan_Win32_Jaik_AMAC_MTB{
	meta:
		description = "Trojan:Win32/Jaik.AMAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 c8 80 e1 65 f6 d0 24 9a 08 c1 30 e1 88 0c 37 8b 7d ?? 8b 45 ?? 40 89 45 ?? 81 fa } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}