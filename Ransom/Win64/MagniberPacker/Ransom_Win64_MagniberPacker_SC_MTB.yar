
rule Ransom_Win64_MagniberPacker_SC_MTB{
	meta:
		description = "Ransom:Win64/MagniberPacker.SC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 03 dd e9 bc 90 01 07 e3 23 88 90 01 04 03 6d 90 01 01 7b 90 01 01 c3 32 ae 90 01 04 e9 90 01 04 e9 90 01 04 fb 04 90 01 01 94 6a 90 01 01 31 b0 90 01 04 a1 90 00 } //02 00 
	condition:
		any of ($a_*)
 
}