
rule Trojan_Win64_Tedy_RB_MTB{
	meta:
		description = "Trojan:Win64/Tedy.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 24 38 48 8d 6c 24 38 48 b8 ba 06 e2 3b 5d 04 } //01 00 
		$a_01_1 = {69 62 68 63 68 6f 63 6a 64 62 2f 6b 66 61 70 69 6f 69 6a 63 69 2f 66 6a 66 6b 64 70 6b 64 63 6f 2f 66 6a 66 6b 64 70 6b 64 63 6f 2f 6b 62 70 63 68 69 6f 6b 69 6c 2e 45 67 63 67 61 65 66 61 6d 63 } //00 00  ibhchocjdb/kfapioijci/fjfkdpkdco/fjfkdpkdco/kbpchiokil.Egcgaefamc
	condition:
		any of ($a_*)
 
}