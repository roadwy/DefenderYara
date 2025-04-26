
rule Trojan_Win32_FraudPack_BB_MTB{
	meta:
		description = "Trojan:Win32/FraudPack.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 d2 42 2b c2 4a f7 d2 36 3e 74 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}