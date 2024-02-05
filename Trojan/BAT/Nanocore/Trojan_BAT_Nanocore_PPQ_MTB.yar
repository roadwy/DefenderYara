
rule Trojan_BAT_Nanocore_PPQ_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.PPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {07 08 07 08 91 03 08 1f 10 5d 91 61 9c 08 17 d6 0c 08 09 31 eb } //00 00 
	condition:
		any of ($a_*)
 
}