
rule HackTool_Win64_Crdrpi_W_MTB{
	meta:
		description = "HackTool:Win64/Crdrpi.W!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 59 53 54 45 4d 5c 43 6f 6e 74 72 6f 6c 53 65 74 30 30 31 5c 53 65 72 76 69 63 65 73 5c 50 6f 72 74 50 72 6f 78 79 5c 76 34 74 6f 76 34 5c 74 63 70 } //1 SYSTEM\ControlSet001\Services\PortProxy\v4tov4\tcp
		$a_01_1 = {49 70 48 6c 70 53 76 63 } //1 IpHlpSvc
		$a_01_2 = {50 6f 72 74 50 72 6f 78 79 } //1 PortProxy
		$a_01_3 = {43 6f 6e 74 72 6f 6c 53 65 72 76 69 63 65 } //1 ControlService
		$a_01_4 = {4f 70 65 6e 53 43 4d 61 6e 61 67 65 72 41 } //1 OpenSCManagerA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}