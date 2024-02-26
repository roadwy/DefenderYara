
rule Trojan_BAT_FormBook_AACR_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AACR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {54 72 61 66 66 69 63 53 69 6d 75 6c 61 74 69 6f 6e 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //02 00  TrafficSimulation.Properties.Resources
		$a_01_1 = {65 35 39 31 65 37 63 35 2d 33 64 65 39 2d 34 37 30 35 2d 38 62 61 35 2d 35 64 33 62 30 34 36 39 36 31 34 37 } //01 00  e591e7c5-3de9-4705-8ba5-5d3b04696147
		$a_01_2 = {47 65 74 50 69 78 65 6c } //00 00  GetPixel
	condition:
		any of ($a_*)
 
}