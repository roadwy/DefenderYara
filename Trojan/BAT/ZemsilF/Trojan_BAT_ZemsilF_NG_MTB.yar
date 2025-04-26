
rule Trojan_BAT_ZemsilF_NG_MTB{
	meta:
		description = "Trojan:BAT/ZemsilF.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 63 61 70 44 6f 74 4e 65 74 2e 50 61 63 6b 65 74 73 2e 49 70 56 34 } //2 PcapDotNet.Packets.IpV4
		$a_01_1 = {24 33 30 30 38 36 65 39 64 2d 38 37 37 61 2d 34 37 65 61 2d 62 31 33 30 2d 35 36 61 66 32 32 34 61 32 38 30 39 } //2 $30086e9d-877a-47ea-b130-56af224a2809
		$a_01_2 = {71 4c 5a 23 2e 72 65 73 6f 75 72 63 65 73 } //1 qLZ#.resources
		$a_01_3 = {50 61 79 6c 6f 61 64 4c 61 79 65 72 } //1 PayloadLayer
		$a_01_4 = {77 69 6e 6c 6f 67 6f 6e 2e 65 78 65 } //1 winlogon.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}