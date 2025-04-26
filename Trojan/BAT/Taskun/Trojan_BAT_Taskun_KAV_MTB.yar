
rule Trojan_BAT_Taskun_KAV_MTB{
	meta:
		description = "Trojan:BAT/Taskun.KAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 67 42 6b 41 47 77 41 62 41 41 41 41 41 41 41 4e 41 41 4b 41 41 45 41 } //3 LgBkAGwAbAAAAAAANAAKAAEA
		$a_01_1 = {50 51 52 4d 42 44 34 45 51 41 51 34 42 45 49 45 4d 41 51 41 41 44 59 41 43 51 41 42 } //4 PQRMBD4EQAQ4BEIEMAQAADYACQAB
		$a_01_2 = {56 67 42 6c 41 48 49 41 63 77 42 70 41 47 38 41 62 67 41 41 41 44 45 41 4d } //5 VgBlAHIAcwBpAG8AbgAAADEAM
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*4+(#a_01_2  & 1)*5) >=12
 
}