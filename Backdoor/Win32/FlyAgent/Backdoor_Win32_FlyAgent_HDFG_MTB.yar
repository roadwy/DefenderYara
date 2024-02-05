
rule Backdoor_Win32_FlyAgent_HDFG_MTB{
	meta:
		description = "Backdoor:Win32/FlyAgent.HDFG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {c1 fe ff f3 35 33 f6 74 08 8b 4e 04 83 c6 08 f3 a4 4a 75 ec } //00 00 
	condition:
		any of ($a_*)
 
}