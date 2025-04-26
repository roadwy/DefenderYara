
rule Trojan_Win32_Lotok_CBV_MTB{
	meta:
		description = "Trojan:Win32/Lotok.CBV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 68 5c dd 04 00 8b f1 6a 00 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}