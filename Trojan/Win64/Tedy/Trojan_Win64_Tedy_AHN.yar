
rule Trojan_Win64_Tedy_AHN{
	meta:
		description = "Trojan:Win64/Tedy.AHN,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 00 53 00 49 00 4f 00 4e 00 5f 00 49 00 4e 00 46 00 4f 00 00 00 00 00 bd 04 ef fe 00 00 01 00 } //10
		$a_01_1 = {70 61 79 6c 6f 61 64 5f 74 65 6d 70 2e 64 6c 6c } //20 payload_temp.dll
		$a_01_2 = {5f 70 61 79 6c 6f 61 64 5f 69 6e 69 74 } //30 _payload_init
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*20+(#a_01_2  & 1)*30) >=60
 
}