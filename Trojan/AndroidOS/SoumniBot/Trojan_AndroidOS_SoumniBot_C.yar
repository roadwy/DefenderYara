
rule Trojan_AndroidOS_SoumniBot_C{
	meta:
		description = "Trojan:AndroidOS/SoumniBot.C,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 6f 66 74 77 61 72 65 61 70 70 2f 42 6f 6f 74 42 72 6f 61 64 63 61 73 74 52 65 63 65 69 76 65 72 } //2 softwareapp/BootBroadcastReceiver
		$a_01_1 = {64 33 4e 7a 4f 69 38 76 64 33 64 33 4c 6d 31 68 61 32 55 32 4f 53 35 70 62 6d 5a 76 4f 6a 67 33 4e 6a 55 3d } //2 d3NzOi8vd3d3Lm1ha2U2OS5pbmZvOjg3NjU=
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}