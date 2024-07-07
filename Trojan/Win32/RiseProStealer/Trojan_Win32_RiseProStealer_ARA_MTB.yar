
rule Trojan_Win32_RiseProStealer_ARA_MTB{
	meta:
		description = "Trojan:Win32/RiseProStealer.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {69 4c 9d 00 91 e9 d1 5b 8b c1 c1 e8 18 33 c1 69 c8 91 e9 d1 5b 89 4c 24 28 85 d2 75 1c f6 c3 01 74 17 8d 47 fd 3b d8 7e 10 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}