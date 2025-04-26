
rule Trojan_Win32_Lotok_CBU_MTB{
	meta:
		description = "Trojan:Win32/Lotok.CBU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {53 56 6a 40 68 00 30 00 00 68 5c dc 04 00 6a 00 8b f1 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}