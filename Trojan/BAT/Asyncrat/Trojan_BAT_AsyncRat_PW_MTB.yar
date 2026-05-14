
rule Trojan_BAT_AsyncRat_PW_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.PW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {03 04 20 8a a5 08 00 58 05 58 61 10 01 03 2a } //3
		$a_00_1 = {74 77 65 72 6a 68 69 74 75 68 71 2e 65 72 79 77 65 72 6b 69 67 73 } //2 twerjhituhq.erywerkigs
		$a_01_2 = {30 64 65 37 61 34 32 30 2d 38 32 61 64 2d 34 65 31 35 2d 38 30 36 62 2d 39 61 33 66 32 39 61 35 62 62 61 64 } //1 0de7a420-82ad-4e15-806b-9a3f29a5bbad
	condition:
		((#a_01_0  & 1)*3+(#a_00_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}