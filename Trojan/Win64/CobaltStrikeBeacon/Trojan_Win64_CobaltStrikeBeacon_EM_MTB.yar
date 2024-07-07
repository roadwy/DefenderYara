
rule Trojan_Win64_CobaltStrikeBeacon_EM_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrikeBeacon.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 c9 4d 8d 40 01 48 83 fa 15 48 0f 45 ca 41 ff c1 42 0f b6 04 11 48 8d 51 01 41 30 40 ff 41 81 f9 cc 01 00 00 72 d9 } //4
		$a_01_1 = {6d 79 73 75 70 65 72 64 75 70 65 72 73 65 63 72 65 74 6b 65 79 } //1 mysuperdupersecretkey
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}