
rule Trojan_Win64_StrelaStealer_GPAA_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.GPAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {6f 75 74 2e 64 6c 6c 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 4d 65 6d 43 70 79 00 53 74 72 43 6d 70 } //2
		$a_01_1 = {78 00 78 2e 31 00 78 2e 31 31 00 78 2e 33 00 78 2e 35 00 78 2e 37 00 78 2e 39 00 79 00 79 2e 31 30 00 79 2e 31 32 00 79 2e 32 00 79 2e 34 00 79 2e 36 00 79 2e } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}