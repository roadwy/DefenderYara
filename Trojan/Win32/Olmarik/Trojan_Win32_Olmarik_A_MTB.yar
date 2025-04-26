
rule Trojan_Win32_Olmarik_A_MTB{
	meta:
		description = "Trojan:Win32/Olmarik.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 6a 3e 33 d2 5b f7 f3 83 fa 1a 7d ?? 80 c2 61 eb ?? 83 fa 34 7d ?? 80 c2 27 eb ?? 80 ea 04 d1 45 fc 88 14 0f 47 3b fe 7c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}