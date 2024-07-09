
rule Trojan_BAT_AgentTesla_MBAM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 04 03 8e 69 5d 91 06 04 1f 16 5d 91 61 28 ?? ?? ?? 0a 03 04 17 58 03 8e 69 5d 91 28 ?? 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d } //1
		$a_01_1 = {45 00 42 00 51 00 38 00 4f 00 35 00 35 00 38 00 45 00 46 00 4a 00 42 00 38 00 34 00 34 00 38 00 46 00 54 00 41 00 37 00 47 00 35 00 } //1 EBQ8O558EFJB8448FTA7G5
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}