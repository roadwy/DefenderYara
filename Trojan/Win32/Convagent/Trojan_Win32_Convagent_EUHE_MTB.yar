
rule Trojan_Win32_Convagent_EUHE_MTB{
	meta:
		description = "Trojan:Win32/Convagent.EUHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 e9 05 03 4d d4 33 d1 8b 45 e0 2b c2 89 45 e0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}