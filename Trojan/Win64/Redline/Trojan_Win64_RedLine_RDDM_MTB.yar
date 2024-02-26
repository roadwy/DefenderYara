
rule Trojan_Win64_RedLine_RDDM_MTB{
	meta:
		description = "Trojan:Win64/RedLine.RDDM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {45 0f b6 ca 46 0f b6 0c 09 44 30 0c 30 48 ff c0 } //00 00 
	condition:
		any of ($a_*)
 
}