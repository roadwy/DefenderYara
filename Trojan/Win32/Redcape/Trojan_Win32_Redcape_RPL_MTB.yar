
rule Trojan_Win32_Redcape_RPL_MTB{
	meta:
		description = "Trojan:Win32/Redcape.RPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 75 e8 8b 5d d4 8a 1c 1e 8b 75 e0 32 1c 0e 8b 4d e4 8b 75 d4 88 1c 31 8b 4d f0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}