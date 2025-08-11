
rule Trojan_Win32_Neoreblamy_NJU_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NJU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 d4 40 89 45 d4 83 7d d4 01 7d 10 8b 45 d4 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}