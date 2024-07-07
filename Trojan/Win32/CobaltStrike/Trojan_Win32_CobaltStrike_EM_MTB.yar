
rule Trojan_Win32_CobaltStrike_EM_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 30 c0 34 01 44 89 c3 44 08 cb 80 f3 01 08 c3 44 89 ca 44 30 c2 41 20 d1 44 20 c2 45 89 c8 41 20 d0 44 30 ca 44 08 c2 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}