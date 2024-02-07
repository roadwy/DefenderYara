
rule Trojan_AndroidOS_Grifthorse_A{
	meta:
		description = "Trojan:AndroidOS/Grifthorse.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 72 65 63 64 65 6c 2f 65 74 64 70 72 6f } //02 00  Lcom/recdel/etdpro
		$a_01_1 = {4c 63 6f 6d 2f 64 73 6c 72 63 6d 2f 66 6f 63 70 72 31 } //02 00  Lcom/dslrcm/focpr1
		$a_01_2 = {74 63 45 45 44 45 75 36 75 53 48 56 4c 45 66 63 34 70 78 62 71 34 } //02 00  tcEEDEu6uSHVLEfc4pxbq4
		$a_01_3 = {32 48 73 69 55 70 56 72 52 73 71 47 56 56 4a 4b 70 35 76 50 56 43 } //01 00  2HsiUpVrRsqGVVJKp5vPVC
		$a_01_4 = {6f 70 65 6e 5f 77 62 3d } //00 00  open_wb=
	condition:
		any of ($a_*)
 
}