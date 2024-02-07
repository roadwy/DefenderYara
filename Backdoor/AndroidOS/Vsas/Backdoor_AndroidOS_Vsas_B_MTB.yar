
rule Backdoor_AndroidOS_Vsas_B_MTB{
	meta:
		description = "Backdoor:AndroidOS/Vsas.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {76 65 6c 6f 63 69 6d 65 74 72 79 2e 61 63 74 69 6f 6e } //01 00  velocimetry.action
		$a_01_1 = {63 6f 6d 2f 73 61 61 73 76 2f 61 70 70 2f 6e 65 74 73 70 65 65 64 } //01 00  com/saasv/app/netspeed
		$a_01_2 = {72 65 73 70 5f 69 6e 66 6f } //01 00  resp_info
		$a_01_3 = {2f 64 70 69 2f 72 65 67 69 73 74 65 72 2e 70 68 70 } //00 00  /dpi/register.php
	condition:
		any of ($a_*)
 
}