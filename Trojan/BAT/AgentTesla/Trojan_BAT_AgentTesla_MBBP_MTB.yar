
rule Trojan_BAT_AgentTesla_MBBP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBBP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {34 00 44 00 2b 00 35 00 41 00 2b 00 39 00 7d 00 3a 00 2b 00 7d 00 33 00 3a 00 3a 00 3a 00 2b 00 7d 00 34 00 3a 00 3a 00 3a 00 2b 00 46 00 46 00 2b 00 46 00 46 00 3a 00 3a 00 2b 00 42 00 } //00 00  4D+5A+9}:+}3:::+}4:::+FF+FF::+B
	condition:
		any of ($a_*)
 
}