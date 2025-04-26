
rule Trojan_Win64_Marte_CCHT_MTB{
	meta:
		description = "Trojan:Win64/Marte.CCHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 d0 01 c0 01 d0 29 c1 89 ca 48 63 c2 0f b6 44 05 ?? 44 31 c0 89 c1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}