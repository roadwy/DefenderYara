
rule Trojan_Win32_Dridex_S_MTB{
	meta:
		description = "Trojan:Win32/Dridex.S!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {32 c1 89 07 59 5a 4a 47 49 75 [0-60] ac 52 51 8b c8 8b 07 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}