
rule Trojan_BAT_LummaC_MBZV_MTB{
	meta:
		description = "Trojan:BAT/LummaC.MBZV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3c 4d 6f 64 75 6c 65 3e 00 43 6f 72 72 65 63 74 00 4d 53 47 5f 4e 45 54 00 4f 62 6a 65 63 74 00 3c 3e 63 5f 5f 44 69 73 70 6c 61 79 43 6c 61 73 73 35 } //1 䴼摯汵㹥䌀牯敲瑣䴀䝓也呅伀橢捥t㸼彣䑟獩汰祡汃獡㕳
		$a_01_1 = {72 69 76 61 74 65 49 6d 70 6c 65 6d 65 6e 74 61 74 69 6f 6e 44 65 74 61 69 6c 73 3e } //1 rivateImplementationDetails>
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}