
rule Backdoor_BAT_Bladabindi_MBZW_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.MBZW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6d 65 6b 61 6c 69 62 65 70 6f 6a 79 68 65 00 71 61 70 69 66 65 78 75 67 61 72 6f 6c 75 72 75 6a 65 00 45 6e 64 49 } //1 敭慫楬敢潰祪敨焀灡晩硥杵牡汯牵橵e湅䥤
		$a_01_1 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}