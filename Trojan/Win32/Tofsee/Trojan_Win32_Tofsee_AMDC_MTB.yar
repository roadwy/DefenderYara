
rule Trojan_Win32_Tofsee_AMDC_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.AMDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff 33 58 83 c3 04 f7 d8 83 c0 [0-0a] 29 d0 89 c2 c7 46 00 00 00 00 00 31 06 8d 76 04 8d 49 04 68 cf 52 40 00 c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}