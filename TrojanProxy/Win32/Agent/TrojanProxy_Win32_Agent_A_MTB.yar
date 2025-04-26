
rule TrojanProxy_Win32_Agent_A_MTB{
	meta:
		description = "TrojanProxy:Win32/Agent.A!MTB,SIGNATURE_TYPE_PEHSTR,23 00 1e 00 05 00 00 "
		
	strings :
		$a_01_0 = {62 69 6b 66 69 72 2e 64 6c 6c } //10 bikfir.dll
		$a_01_1 = {6b 2e 64 69 6c 6d 6f 73 6f 66 72 6f 61 64 2e 63 6f 6d } //10 k.dilmosofroad.com
		$a_01_2 = {32 35 66 30 37 32 35 36 2d 33 62 34 36 2d 34 35 33 31 2d 61 61 33 65 2d 65 31 37 32 39 64 39 61 61 37 63 62 } //5 25f07256-3b46-4531-aa3e-e1729d9aa7cb
		$a_01_3 = {36 30 66 38 38 39 36 62 2d 61 34 33 37 2d 34 65 37 39 2d 39 65 32 39 2d 39 36 35 32 32 63 61 38 38 63 34 63 } //5 60f8896b-a437-4e79-9e29-96522ca88c4c
		$a_01_4 = {ac c0 c0 03 aa e2 f9 61 c9 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*10) >=30
 
}