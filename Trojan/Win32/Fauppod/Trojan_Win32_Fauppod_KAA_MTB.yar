
rule Trojan_Win32_Fauppod_KAA_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 e5 8a 45 [0-0f] 88 c2 02 15 [0-32] 30 c8 0f b6 c0 5d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}