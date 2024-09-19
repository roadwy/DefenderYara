
rule Trojan_AndroidOS_Gepew_A{
	meta:
		description = "Trojan:AndroidOS/Gepew.A,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 6b 62 73 2e 70 68 70 3f 6d 3d 41 70 69 26 61 3d } //2 /kbs.php?m=Api&a=
		$a_01_1 = {43 6f 6e 74 61 63 74 26 73 74 61 74 75 73 3d 31 26 69 6d 73 69 3d } //2 Contact&status=1&imsi=
		$a_01_2 = {53 4d 53 53 65 6e 64 43 6f 6d 70 6c 61 74 65 26 74 6f 3d } //2 SMSSendComplate&to=
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}