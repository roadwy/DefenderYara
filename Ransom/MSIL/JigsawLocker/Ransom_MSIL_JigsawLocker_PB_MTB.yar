
rule Ransom_MSIL_JigsawLocker_PB_MTB{
	meta:
		description = "Ransom:MSIL/JigsawLocker.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {42 69 74 63 6f 69 6e 53 74 65 61 6c 65 72 2e 65 78 65 } //1 BitcoinStealer.exe
		$a_01_1 = {4e 00 69 00 74 00 72 00 6f 00 20 00 50 00 44 00 46 00 } //1 Nitro PDF
		$a_01_2 = {50 00 72 00 69 00 6d 00 6f 00 50 00 44 00 46 00 2e 00 65 00 78 00 65 00 } //1 PrimoPDF.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}