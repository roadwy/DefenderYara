
rule Trojan_AndroidOS_Fakeapp_HT{
	meta:
		description = "Trojan:AndroidOS/Fakeapp.HT,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {56 31 68 77 54 31 55 79 56 6c 64 6a 52 6d 68 54 59 6d 78 46 4f 51 } //1 V1hwT1UyVldjRmhTYmxFOQ
		$a_01_1 = {56 32 74 6a 65 46 59 79 56 6c 68 55 57 47 78 70 55 30 5a 77 63 46 64 75 62 33 64 50 55 54 30 39 } //1 V2tjeFYyVlhUWGxpU0ZwcFdub3dPUT09
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}