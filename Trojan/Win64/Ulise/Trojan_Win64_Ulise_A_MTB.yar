
rule Trojan_Win64_Ulise_A_MTB{
	meta:
		description = "Trojan:Win64/Ulise.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {e6 4f d2 2a 26 48 28 6e 16 a3 ?? ?? ?? ?? ?? ?? ?? ?? 32 50 b9 30 55 d9 54 8a d4 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}