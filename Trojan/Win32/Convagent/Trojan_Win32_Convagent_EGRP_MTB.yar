
rule Trojan_Win32_Convagent_EGRP_MTB{
	meta:
		description = "Trojan:Win32/Convagent.EGRP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 55 fc 0f be 02 83 f0 34 8b 4d f8 03 4d fc 88 01 ?? ?? ba 01 00 00 00 6b c2 42 8b 4d f8 c6 04 01 00 8b 45 f8 8b e5 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}