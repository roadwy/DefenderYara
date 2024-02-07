
rule Ransom_MSIL_Weed_DA_MTB{
	meta:
		description = "Ransom:MSIL/Weed.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {52 61 6e 73 6f 6d 77 61 72 65 2e 74 6f 72 } //01 00  Ransomware.tor
		$a_81_1 = {2e 77 65 65 64 } //01 00  .weed
		$a_81_2 = {2e 6f 6e 69 6f 6e } //01 00  .onion
		$a_81_3 = {77 61 6c 6c 70 61 70 65 72 2e 6a 70 67 } //00 00  wallpaper.jpg
	condition:
		any of ($a_*)
 
}