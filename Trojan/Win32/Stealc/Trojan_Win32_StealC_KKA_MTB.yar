
rule Trojan_Win32_StealC_KKA_MTB{
	meta:
		description = "Trojan:Win32/StealC.KKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 0c 30 04 31 83 7d 0c 0f 75 57 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}