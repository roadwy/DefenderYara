
rule Trojan_Win64_Zudochka_MTB{
	meta:
		description = "Trojan:Win64/Zudochka!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 45 c7 30 44 0d c8 49 03 cf 48 83 f9 ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}