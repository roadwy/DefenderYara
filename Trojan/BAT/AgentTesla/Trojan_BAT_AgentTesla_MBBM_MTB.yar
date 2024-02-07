
rule Trojan_BAT_AgentTesla_MBBM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {34 44 2d 35 41 2d 39 30 3f 2d 30 33 3f 3f 3f 2d 30 34 3f 3f 3f 2d 46 46 2d 46 46 3f 3f 2d 42 38 3f 3f 3f 3f 3f 3f 3f 2d 34 30 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 2d 38 30 } //00 00  4D-5A-90?-03???-04???-FF-FF??-B8???????-40???????????????????????????????????-80
	condition:
		any of ($a_*)
 
}