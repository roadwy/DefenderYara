
rule Trojan_AndroidOS_EvilInst_A{
	meta:
		description = "Trojan:AndroidOS/EvilInst.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 64 61 62 39 36 32 39 2d 33 39 31 66 2d 34 37 66 33 2d 39 63 37 36 2d 65 31 33 64 61 65 30 66 65 65 39 33 } //01 00  1dab9629-391f-47f3-9c76-e13dae0fee93
		$a_01_1 = {76 6e 69 66 6f 6f 64 2e 63 6f 6d } //01 00  vnifood.com
		$a_01_2 = {6f 6e 65 73 69 67 6e 61 6c 35 2e 6d 6f 64 6f 62 6f 6d 63 6f 2e 63 6f 6d } //00 00  onesignal5.modobomco.com
	condition:
		any of ($a_*)
 
}