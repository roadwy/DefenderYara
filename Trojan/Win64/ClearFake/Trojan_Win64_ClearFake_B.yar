
rule Trojan_Win64_ClearFake_B{
	meta:
		description = "Trojan:Win64/ClearFake.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c9 0f 31 48 c1 e2 20 48 09 c2 48 39 da 0f ?? ?? ?? ?? ?? 48 89 d9 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}