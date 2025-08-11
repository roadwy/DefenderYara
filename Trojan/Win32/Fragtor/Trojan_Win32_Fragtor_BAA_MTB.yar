
rule Trojan_Win32_Fragtor_BAA_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b d0 31 13 83 45 ec 04 83 c3 04 8b 45 ec 3b 45 dc 72 92 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}