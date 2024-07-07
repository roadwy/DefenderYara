
rule Trojan_AndroidOS_FakeJobOffer_A_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeJobOffer.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 62 69 67 67 62 6f 73 73 36 2f 54 61 74 61 73 68 6f 77 } //1 com/biggboss6/Tatashow
		$a_01_1 = {61 64 2e 64 6f 75 62 6c 65 63 6c 69 63 6b 2e 6e 65 74 2f 4e 36 37 31 34 2f 61 64 6a 2f 53 41 41 56 4e 41 6e 64 72 6f 69 64 57 65 62 } //1 ad.doubleclick.net/N6714/adj/SAAVNAndroidWeb
		$a_01_2 = {74 72 61 63 6b 56 64 6f 70 69 61 } //1 trackVdopia
		$a_01_3 = {74 72 61 63 6b 5a 65 73 74 41 64 7a } //1 trackZestAdz
		$a_01_4 = {66 65 74 63 68 65 64 48 6f 6d 65 44 61 74 61 } //1 fetchedHomeData
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}