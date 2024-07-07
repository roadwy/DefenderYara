
rule Trojan_BAT_Taskun_MBFU_MTB{
	meta:
		description = "Trojan:BAT/Taskun.MBFU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {34 00 44 00 35 00 41 00 39 00 2a 00 2a 00 33 00 2a 00 2a 00 2a 00 30 00 34 00 2a 00 2a 00 2a 00 46 00 46 00 46 00 46 00 2a 00 2a 00 42 00 38 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 34 00 } //1 4D5A9**3***04***FFFF**B8*******4
	condition:
		((#a_01_0  & 1)*1) >=1
 
}