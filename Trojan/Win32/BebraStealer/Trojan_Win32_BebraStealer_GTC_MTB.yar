
rule Trojan_Win32_BebraStealer_GTC_MTB{
	meta:
		description = "Trojan:Win32/BebraStealer.GTC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 0c 8b 45 08 01 f2 8d 0c b0 31 c0 89 d3 8a 14 83 30 14 01 40 83 f8 90 01 01 75 f4 46 83 fe 90 01 01 75 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}