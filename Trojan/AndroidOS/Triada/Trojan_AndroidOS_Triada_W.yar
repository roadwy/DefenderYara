
rule Trojan_AndroidOS_Triada_W{
	meta:
		description = "Trojan:AndroidOS/Triada.W,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2f 73 79 73 74 65 6d 2f 62 69 6e 2f 64 61 65 6d 6f 6e 6e 69 73 20 2d 2d 61 75 74 6f 2d 64 61 65 6d 6f 6e 20 26 } //1 /system/bin/daemonnis --auto-daemon &
		$a_01_1 = {72 6d 20 2f 73 79 73 74 65 6d 2f 62 69 6e 2f 64 61 65 6d 6f 6e 6e 69 73 3b } //1 rm /system/bin/daemonnis;
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}