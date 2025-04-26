
rule Trojan_AndroidOS_Spynote_RH{
	meta:
		description = "Trojan:AndroidOS/Spynote.RH,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6d 6d 61 72 64 64 61 72 6d 6a 74 74 6a 78 65 6b 69 72 6a 74 73 75 68 63 63 7a 64 68 64 62 64 71 67 72 6e 78 6d 74 73 6f 78 6d 73 65 78 6a 6d 64 72 6f 36 6c 62 6d 4e 75 31 38 } //1 mmarddarmjttjxekirjtsuhcczdhdbdqgrnxmtsoxmsexjmdro6lbmNu18
		$a_01_1 = {70 64 62 61 66 6d 64 6f 65 63 31 30 32 30 } //1 pdbafmdoec1020
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}