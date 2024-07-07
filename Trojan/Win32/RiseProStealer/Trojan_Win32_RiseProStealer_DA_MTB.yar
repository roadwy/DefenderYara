
rule Trojan_Win32_RiseProStealer_DA_MTB{
	meta:
		description = "Trojan:Win32/RiseProStealer.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {69 0c b3 95 e9 d1 5b 46 69 ff 95 e9 d1 5b 8b c1 c1 e8 18 33 c1 69 c8 95 e9 d1 5b 33 f9 3b f5 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}