
rule Trojan_BAT_Netwire_XNR_MTB{
	meta:
		description = "Trojan:BAT/Netwire.XNR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {06 08 8f 0a 00 00 01 25 47 03 08 1f 10 5d 91 61 d2 52 00 08 17 d6 0c 08 07 fe 02 16 fe 01 0d 09 2d dd } //00 00 
	condition:
		any of ($a_*)
 
}