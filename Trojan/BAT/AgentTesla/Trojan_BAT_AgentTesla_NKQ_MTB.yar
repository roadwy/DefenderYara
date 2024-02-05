
rule Trojan_BAT_AgentTesla_NKQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NKQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 04 8e 69 1e 5a 6f 90 01 03 0a 00 07 04 6f 90 01 03 0a 00 07 05 8e 69 1e 5a 6f 90 01 03 0a 00 07 05 6f 90 01 03 0a 00 07 6f 90 01 03 0a 0c 00 03 73 90 01 03 0a 0d 00 09 08 16 73 90 01 03 0a 13 04 00 03 8e 69 8d 90 01 03 01 13 05 11 04 11 05 16 03 8e 69 6f 90 01 03 0a 13 06 11 05 11 06 28 90 01 03 2b 28 90 01 03 2b 0a 00 de 0d 90 00 } //01 00 
		$a_80_1 = {51 57 31 7a 61 56 4e 6a 59 57 35 43 64 57 5a 6d 5a 58 49 3d } //QW1zaVNjYW5CdWZmZXI=  01 00 
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_80_3 = {50 72 6f 62 61 62 69 6c 69 74 79 20 64 65 6e 73 69 74 79 20 66 75 6e 63 74 69 6f 6e } //Probability density function  01 00 
		$a_80_4 = {2f 70 61 67 65 73 2f 70 61 67 65 5f 63 68 61 72 74 2e 78 61 6d 6c } ///pages/page_chart.xaml  01 00 
		$a_80_5 = {37 38 74 37 39 7c 38 39 54 35 35 7c 36 39 38 79 39 38 36 7c } //78t79|89T55|698y986|  00 00 
	condition:
		any of ($a_*)
 
}