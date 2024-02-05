
rule Trojan_AndroidOS_SmsThief_Z{
	meta:
		description = "Trojan:AndroidOS/SmsThief.Z,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {26 61 63 74 69 6f 6e 3d 73 6d 73 26 6e 65 74 77 6f 72 6b 3d } //02 00 
		$a_01_1 = {26 63 76 76 32 3d 31 26 6d 6f 6e 74 68 3d 32 26 79 65 61 72 3d 33 26 6d 6f 64 65 6c 3d } //02 00 
		$a_01_2 = {26 6c 79 64 69 61 3d 6c 6f 67 69 6e } //00 00 
	condition:
		any of ($a_*)
 
}