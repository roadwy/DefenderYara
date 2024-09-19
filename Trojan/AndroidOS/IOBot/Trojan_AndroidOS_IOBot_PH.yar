
rule Trojan_AndroidOS_IOBot_PH{
	meta:
		description = "Trojan:AndroidOS/IOBot.PH,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2f 61 70 70 2f 38 63 35 65 31 34 38 39 65 35 33 30 64 64 36 63 64 33 39 62 } //1 /app/8c5e1489e530dd6cd39b
		$a_01_1 = {77 73 73 3a 2f 2f 61 70 69 2e 73 70 61 63 65 78 6d 6d 6f 62 69 6c 65 2e 63 6f 6d 2f 77 73 2f 6d 6f 62 69 6c 65 2f } //1 wss://api.spacexmmobile.com/ws/mobile/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}