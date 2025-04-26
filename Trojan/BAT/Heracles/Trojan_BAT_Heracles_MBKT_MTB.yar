
rule Trojan_BAT_Heracles_MBKT_MTB{
	meta:
		description = "Trojan:BAT/Heracles.MBKT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {24 37 30 34 39 65 31 62 61 2d 61 65 64 31 2d 34 64 61 62 2d 62 31 30 34 2d 30 63 65 31 63 34 37 64 33 65 62 63 } //1 $7049e1ba-aed1-4dab-b104-0ce1c47d3ebc
		$a_01_1 = {4c 75 6d 62 65 72 52 61 63 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //1 LumberRacer.Properties.Resources.resource
		$a_01_2 = {4c 75 6d 62 65 72 52 61 63 65 72 2e 65 78 65 } //1 LumberRacer.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}