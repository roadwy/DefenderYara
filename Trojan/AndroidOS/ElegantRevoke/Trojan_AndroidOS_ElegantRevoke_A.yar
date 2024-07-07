
rule Trojan_AndroidOS_ElegantRevoke_A{
	meta:
		description = "Trojan:AndroidOS/ElegantRevoke.A,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {76 70 6e 75 73 65 72 32 } //1 vpnuser2
		$a_01_1 = {56 70 4e 75 24 33 52 } //1 VpNu$3R
		$a_01_2 = {68 74 74 70 3a 2f 2f 63 64 73 61 2e 78 79 7a } //1 http://cdsa.xyz
		$a_01_3 = {54 61 70 20 74 6f 20 67 65 74 20 61 20 62 65 74 74 65 72 20 75 73 65 72 20 65 78 70 65 72 69 65 6e 63 65 20 4f 66 20 41 6e 64 72 6f 69 64 } //1 Tap to get a better user experience Of Android
		$a_01_4 = {53 63 72 65 65 6e 73 68 6f 74 20 4d 6f 64 75 6c 65 20 69 73 20 72 75 6e 6e 69 6e 67 2e } //1 Screenshot Module is running.
		$a_01_5 = {41 70 69 2f 49 73 52 75 6e 41 75 64 69 6f 52 65 63 6f 72 64 65 72 } //1 Api/IsRunAudioRecorder
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}