
rule Trojan_Win32_Dorv_S_MTB{
	meta:
		description = "Trojan:Win32/Dorv.S!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 13 31 16 ad 3b f3 75 f9 e9 90 01 02 ff ff 90 0a 25 00 8d 35 90 01 04 8d 1d 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}