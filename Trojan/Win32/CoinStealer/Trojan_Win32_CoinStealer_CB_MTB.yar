
rule Trojan_Win32_CoinStealer_CB_MTB{
	meta:
		description = "Trojan:Win32/CoinStealer.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2a c1 2a c1 c0 c0 05 34 51 c0 c0 05 aa 4a 0f 85 } //1
		$a_01_1 = {2a c1 32 c1 32 c1 34 51 2a c1 32 c1 c0 c8 05 32 c1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}