
rule Trojan_BAT_ClipBanker_SG_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.SG!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {7a 67 66 6e 2e 4d 79 } //2 zgfn.My
		$a_01_1 = {66 67 78 67 2e 65 78 65 } //1 fgxg.exe
		$a_01_2 = {24 61 33 33 39 32 64 63 33 2d 64 38 66 66 2d 34 30 36 39 2d 38 37 38 32 2d 30 61 65 38 61 31 31 32 35 32 38 31 } //1 $a3392dc3-d8ff-4069-8782-0ae8a1125281
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}