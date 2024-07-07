
rule Trojan_Win32_Copak_FV_MTB{
	meta:
		description = "Trojan:Win32/Copak.FV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {68 d8 85 40 00 58 e8 90 01 04 01 c9 b9 90 01 04 31 06 81 c6 90 01 04 39 d6 75 e2 83 ec 04 89 3c 24 8b 0c 24 83 c4 04 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}