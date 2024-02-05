
rule Ransom_Win64_BlackByte_FG_MTB{
	meta:
		description = "Ransom:Win64/BlackByte.FG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 8b c2 4d 8d 49 01 99 41 ff c2 f7 ff 48 63 c2 44 0f b6 04 18 45 30 41 ff 45 3b d3 7c e2 } //00 00 
	condition:
		any of ($a_*)
 
}