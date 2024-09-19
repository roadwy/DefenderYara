
rule Trojan_BAT_LummaStealer_AMAM_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.AMAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {6a 54 6d 5a 66 53 64 53 52 69 57 49 72 74 49 5a 44 76 42 68 67 } //jTmZfSdSRiWIrtIZDvBhg  1
		$a_80_1 = {48 41 70 51 67 76 6a 7a 53 79 64 72 6c 6d 50 62 78 50 50 6e 78 65 64 } //HApQgvjzSydrlmPbxPPnxed  1
		$a_80_2 = {48 51 58 6c 41 44 79 46 56 6d 58 47 44 42 6e 6e 57 66 5a 4f 65 47 77 47 56 49 70 57 } //HQXlADyFVmXGDBnnWfZOeGwGVIpW  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}