
rule Ransom_Win64_MagniberPacker_SG_MTB{
	meta:
		description = "Ransom:Win64/MagniberPacker.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {14 71 8d 93 90 01 04 e5 90 01 01 19 db 0d 90 01 04 35 90 01 04 a5 4b e1 90 01 01 ae de 72 90 01 01 6c ba 90 01 04 80 8d 90 01 07 5d e9 90 01 04 b4 fe 31 ae 90 01 04 ef 90 00 } //02 00 
	condition:
		any of ($a_*)
 
}