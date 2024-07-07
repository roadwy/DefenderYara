
rule Trojan_Win32_DarkKomet_SA_MTB{
	meta:
		description = "Trojan:Win32/DarkKomet.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 4c 24 90 01 01 c1 e8 90 01 01 40 89 44 24 90 01 01 8d 9b 90 01 04 0f b6 46 90 01 01 8d 3c 31 32 03 88 07 0f b6 46 90 01 01 32 43 90 01 01 88 42 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}