
rule Trojan_BAT_Formbook_NV_MTB{
	meta:
		description = "Trojan:BAT/Formbook.NV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {57 bd a2 3d 09 07 00 00 00 00 00 00 00 00 00 00 01 } //1
		$a_01_1 = {53 00 47 00 34 00 30 00 46 00 46 00 5a 00 35 00 38 00 34 00 48 00 58 00 47 00 35 00 47 00 54 00 45 00 35 00 35 00 35 00 50 00 57 00 } //1 SG40FFZ584HXG5GTE555PW
		$a_01_2 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 52 00 65 00 66 00 6c 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 } //1 System.Reflection.Assembly
		$a_01_3 = {24 32 34 30 61 35 66 33 33 2d 39 63 63 61 2d 34 36 39 66 2d 61 35 39 31 2d 33 35 36 30 33 33 38 66 38 62 33 34 } //1 $240a5f33-9cca-469f-a591-3560338f8b34
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}