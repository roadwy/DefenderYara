
rule Trojan_Win32_HeavensGate_GVA_MTB{
	meta:
		description = "Trojan:Win32/HeavensGate.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 75 14 8b 45 10 01 d0 0f b6 08 8b 55 08 8b 45 f4 01 d0 31 cb 89 da 88 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}