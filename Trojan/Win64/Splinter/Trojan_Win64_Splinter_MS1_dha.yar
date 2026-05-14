
rule Trojan_Win64_Splinter_MS1_dha{
	meta:
		description = "Trojan:Win64/Splinter.MS1!dha,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {49 6d 70 6c 61 6e 74 20 67 72 61 63 65 66 75 6c 20 73 68 75 74 64 6f 77 6e } //10 Implant graceful shutdown
		$a_01_1 = {73 74 72 75 63 74 20 49 6d 70 6c 61 6e 74 49 64 } //10 struct ImplantId
		$a_01_2 = {73 74 72 75 63 74 20 49 6d 70 6c 61 6e 74 43 6f 6e 66 69 67 } //10 struct ImplantConfig
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=30
 
}