
rule Trojan_BAT_AgentTesla_RDAA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {36 62 34 33 31 38 31 63 2d 30 61 30 61 2d 34 33 35 34 2d 62 65 33 65 2d 39 63 33 35 35 62 31 30 37 32 64 33 } //01 00  6b43181c-0a0a-4354-be3e-9c355b1072d3
		$a_01_1 = {41 56 47 20 53 65 63 75 72 65 56 50 4e } //01 00  AVG SecureVPN
		$a_01_2 = {43 73 65 71 6e 6d 68 } //01 00  Cseqnmh
		$a_01_3 = {50 72 6f 64 75 63 65 72 73 } //00 00  Producers
	condition:
		any of ($a_*)
 
}