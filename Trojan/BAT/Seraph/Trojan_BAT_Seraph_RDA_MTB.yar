
rule Trojan_BAT_Seraph_RDA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 33 64 39 32 37 39 61 2d 39 30 33 63 2d 34 30 39 34 2d 62 66 34 32 2d 61 38 62 66 32 38 34 32 30 63 39 64 } //1 f3d9279a-903c-4094-bf42-a8bf28420c9d
		$a_01_1 = {36 34 36 33 32 37 62 66 2d 32 38 64 34 2d 34 37 34 39 2d 38 31 38 34 2d 63 61 33 36 38 65 35 33 63 33 66 64 } //1 646327bf-28d4-4749-8184-ca368e53c3fd
		$a_01_2 = {44 65 73 69 72 65 2e 65 78 65 } //1 Desire.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}