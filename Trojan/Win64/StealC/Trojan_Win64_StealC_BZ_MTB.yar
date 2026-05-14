
rule Trojan_Win64_StealC_BZ_MTB{
	meta:
		description = "Trojan:Win64/StealC.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 1c 0a 83 c3 94 88 1c 11 48 ff c2 48 39 d0 7f ee } //2
		$a_81_1 = {4c 30 71 37 6d 6b 61 6c 2d 59 36 6f 4b 31 46 41 41 36 33 2d 2f 6d 5a 59 72 57 30 56 6c 61 42 5a 63 6d 70 52 2d 32 4b 39 74 2f } //1 L0q7mkal-Y6oK1FAA63-/mZYrW0VlaBZcmpR-2K9t/
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*1) >=3
 
}