
rule Trojan_BAT_SnakeKeyLogger_RDCB_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {39 64 31 32 39 36 35 35 2d 36 63 61 33 2d 34 39 30 30 2d 61 32 66 32 2d 61 33 62 62 37 39 65 34 39 31 63 63 } //2 9d129655-6ca3-4900-a2f2-a3bb79e491cc
		$a_01_1 = {56 4d 77 61 72 65 20 57 6f 72 6b 73 74 61 74 69 6f 6e } //1 VMware Workstation
		$a_01_2 = {50 6c 61 79 65 72 } //1 Player
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}