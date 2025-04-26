
rule Trojan_Win32_Fragtor_GKN_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.GKN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c8 0f af c2 02 04 32 30 04 19 42 80 3c 32 00 75 ee } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}