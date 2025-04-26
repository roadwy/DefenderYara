
rule Trojan_BAT_NjRat_NEDV_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEDV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 35 61 37 38 33 37 66 2d 39 36 34 31 2d 34 61 66 30 2d 62 61 30 36 2d 61 33 65 36 38 66 37 35 31 38 39 64 } //5 f5a7837f-9641-4af0-ba06-a3e68f75189d
		$a_01_1 = {30 2e 65 78 65 } //2 0.exe
		$a_01_2 = {67 65 74 5f 45 6e 74 72 79 50 6f 69 6e 74 } //1 get_EntryPoint
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=9
 
}