
rule Trojan_BAT_Taskun_MBWQ_MTB{
	meta:
		description = "Trojan:BAT/Taskun.MBWQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {34 00 44 00 35 00 41 00 39 00 2d 00 2d 00 33 00 2d 00 2d 00 2d 00 30 00 34 00 2d 00 2d 00 2d 00 46 00 46 00 46 00 46 00 2d 00 2d 00 42 00 38 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 34 00 } //2 4D5A9--3---04---FFFF--B8-------4
		$a_01_1 = {45 00 31 00 46 00 42 00 41 00 30 00 45 00 2d 00 42 00 34 00 30 00 39 00 43 00 44 00 32 00 31 00 42 00 38 00 30 00 31 00 34 00 43 00 43 00 44 00 32 00 31 00 35 00 34 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}