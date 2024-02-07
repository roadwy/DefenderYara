
rule Trojan_AndroidOS_Ahmythspy_G{
	meta:
		description = "Trojan:AndroidOS/Ahmythspy.G,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 65 74 46 61 6b 65 72 43 61 6c 6c } //01 00  setFakerCall
		$a_00_1 = {78 30 30 30 30 63 61 } //01 00  x0000ca
		$a_00_2 = {2f 61 70 69 2f 73 69 67 6e 61 6c 2f } //01 00  /api/signal/
		$a_00_3 = {26 64 65 66 61 75 6c 74 5f 64 69 61 6c 65 72 3d } //00 00  &default_dialer=
	condition:
		any of ($a_*)
 
}