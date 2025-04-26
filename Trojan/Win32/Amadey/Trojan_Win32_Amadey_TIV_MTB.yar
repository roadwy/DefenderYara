
rule Trojan_Win32_Amadey_TIV_MTB{
	meta:
		description = "Trojan:Win32/Amadey.TIV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 89 7d fc e8 ?? ?? ?? ?? 8b 45 08 59 8a 4d fc 03 c6 30 08 83 fb 0f 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}