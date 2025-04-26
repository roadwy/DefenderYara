
rule Trojan_BAT_Jalapeno_VG_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.VG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {06 11 05 7e ?? 00 00 04 11 05 91 20 82 00 00 00 61 d2 9c 11 05 17 58 13 05 20 ?? ?? ?? ?? 00 fe 0e [0-06] fe 0d 09 [0-04] 48 68 d3 13 08 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}