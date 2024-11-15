
rule Trojan_Win64_MalDrv_B_MTB{
	meta:
		description = "Trojan:Win64/MalDrv.B!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 65 6e 64 54 6f } //1 SendTo
		$a_01_1 = {52 65 63 65 69 76 65 46 72 6f 6d } //1 ReceiveFrom
		$a_01_2 = {41 63 63 65 70 74 } //1 Accept
		$a_01_3 = {31 30 33 2e 31 31 37 2e 31 32 31 2e 31 36 30 } //1 103.117.121.160
		$a_01_4 = {48 65 6c 6c 6f 20 44 72 69 76 65 72 55 6e 4c 6f 61 64 } //1 Hello DriverUnLoad
		$a_01_5 = {48 65 6c 6c 6f 20 44 72 69 76 65 72 45 6e 74 72 79 } //1 Hello DriverEntry
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}