
rule Trojan_BAT_CryptMiner_MBXT_MTB{
	meta:
		description = "Trojan:BAT/CryptMiner.MBXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 75 69 50 70 54 4a 78 6c 67 52 71 43 41 48 37 32 6c 00 56 67 30 78 6f 4c 52 33 51 6e 78 35 6f 4f 53 4d 38 65 00 4e 47 70 69 } //3 畗偩呰硊杬煒䅃㝈氲嘀で潸剌儳确漵协㡍e䝎楰
		$a_01_1 = {53 63 6f 75 74 56 65 72 69 74 79 5f 42 6c 75 65 50 61 72 6b 61 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 ScoutVerity_BlueParka.Resources.resources
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}