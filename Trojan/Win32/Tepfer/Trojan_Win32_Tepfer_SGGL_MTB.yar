
rule Trojan_Win32_Tepfer_SGGL_MTB{
	meta:
		description = "Trojan:Win32/Tepfer.SGGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {57 33 c9 89 5d f8 8b c6 8b 7e 10 47 83 7e 14 10 72 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}