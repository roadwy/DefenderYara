
rule Trojan_Win32_Fragtor_RP_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 85 9c bd ff ff 30 84 0d 9d bd ff ff 41 83 f9 17 72 ed } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}