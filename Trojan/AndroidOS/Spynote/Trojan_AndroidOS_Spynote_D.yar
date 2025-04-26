
rule Trojan_AndroidOS_Spynote_D{
	meta:
		description = "Trojan:AndroidOS/Spynote.D,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {65 63 68 6f 20 22 44 6f 20 49 20 68 61 76 65 20 72 6f 6f 74 3f 22 20 3e 2f 73 79 73 74 65 6d 2f 73 64 2f 74 65 6d 70 6f 72 61 72 79 2e 74 78 74 } //1 echo "Do I have root?" >/system/sd/temporary.txt
		$a_00_1 = {2f 41 75 64 69 6f 52 65 63 6f 72 64 65 72 2e 77 61 76 } //1 /AudioRecorder.wav
		$a_00_2 = {41 72 72 61 79 44 6e 73 5f 4b 65 79 } //1 ArrayDns_Key
		$a_00_3 = {4e 61 6d 65 5f 4b 65 79 } //1 Name_Key
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}