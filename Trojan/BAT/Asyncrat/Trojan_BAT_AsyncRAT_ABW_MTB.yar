
rule Trojan_BAT_AsyncRAT_ABW_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.ABW!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 69 64 64 65 6e 52 44 50 5f 4c 6f 61 64 } //1 HiddenRDP_Load
		$a_01_1 = {52 61 6e 73 6f 6d 77 61 72 65 5f 4c 6f 61 64 } //1 Ransomware_Load
		$a_01_2 = {4b 65 79 6c 6f 61 67 67 61 72 5f 4c 6f 61 64 } //1 Keyloaggar_Load
		$a_01_3 = {52 65 6d 6f 74 65 41 70 70 5f 4c 6f 61 64 } //1 RemoteApp_Load
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}