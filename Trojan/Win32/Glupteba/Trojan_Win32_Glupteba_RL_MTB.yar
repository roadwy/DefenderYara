
rule Trojan_Win32_Glupteba_RL_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {c1 ea 05 c7 05 90 01 04 84 10 d6 cb c7 05 90 01 04 ff ff ff ff 89 54 24 90 01 01 8b 84 24 90 01 04 01 44 24 90 01 01 8b 4c 24 90 01 01 33 cf 33 ce 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}