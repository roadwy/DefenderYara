
rule Trojan_Win32_BadJoke_EAOC_MTB{
	meta:
		description = "Trojan:Win32/BadJoke.EAOC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b d0 0f be c8 c1 ea 0e 8b d8 80 e2 0e c1 eb 05 0f be d2 0f af d1 8a c8 22 cb 02 c9 02 d1 2a d3 88 94 05 78 56 fc ff 40 3d 80 a9 03 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}