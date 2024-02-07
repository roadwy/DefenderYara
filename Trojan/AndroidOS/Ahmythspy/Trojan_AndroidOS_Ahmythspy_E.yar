
rule Trojan_AndroidOS_Ahmythspy_E{
	meta:
		description = "Trojan:AndroidOS/Ahmythspy.E,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 6d 61 6c 75 6b 61 2e 6c 61 74 69 6d 61 2e 4e 4c 53 43 4f 4e 54 52 4f 4c } //02 00  com.maluka.latima.NLSCONTROL
		$a_00_1 = {63 6f 6d 2e 68 61 78 34 75 73 2e 68 61 78 72 61 74 } //01 00  com.hax4us.haxrat
		$a_00_2 = {2f 4d 61 69 6e 53 65 72 76 69 63 65 24 } //00 00  /MainService$
	condition:
		any of ($a_*)
 
}