
rule Trojan_BAT_AsyncRat_PV_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.PV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {03 04 20 8a a5 08 00 58 05 58 61 10 01 03 2a } //4
		$a_01_1 = {65 72 79 77 65 77 65 72 79 77 65 79 2e 79 6a 77 65 72 75 79 69 6a 77 65 69 72 } //2 erywewerywey.yjweruyijweir
		$a_01_2 = {24 30 64 65 37 61 34 32 30 2d 38 32 61 64 2d 34 65 31 35 2d 38 30 36 62 2d 39 61 33 66 32 39 61 35 62 62 61 64 } //1 $0de7a420-82ad-4e15-806b-9a3f29a5bbad
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=7
 
}