
rule Trojan_Win32_Fragtor_GVA_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 02 8d 52 01 c0 c8 04 8d 49 01 34 a5 46 88 41 ff 8b 45 44 03 c0 3b f0 72 e6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}