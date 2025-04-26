
rule Trojan_Win32_RedLineStealer_RPS_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.RPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 0c 69 c7 e8 ae e9 71 30 04 1a 43 eb d7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}