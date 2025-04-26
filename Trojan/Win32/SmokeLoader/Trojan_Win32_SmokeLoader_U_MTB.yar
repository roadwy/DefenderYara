
rule Trojan_Win32_SmokeLoader_U_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.U!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 0c 01 45 fc 8b 45 fc 31 45 08 8b 45 08 8b e5 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}